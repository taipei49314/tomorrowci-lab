#!/usr/bin/env python3
"""Verify annotated-tag promotion eligibility without publishing anything."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import candidate_manifest
import external_authorization
import oci_candidate
from version_contract import is_semver

KIND = "tomorrowci.tag-promotion-qualification-index.v1"
STATUS = "ELIGIBLE_ONLY_NOT_PUBLISH_AUTHORITY"
MANIFEST_NAME = candidate_manifest.MANIFEST_NAME
CHECKSUMS_NAME = candidate_manifest.CHECKSUMS_NAME
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
ASSET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
TAGGER = re.compile(r"^tagger .+ <[^<>\r\n]+> [0-9]+ [+-][0-9]{4}$")
MAX_FILE = 1024 * 1024 * 1024
MAX_FILES = 64
READ_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class _FileSnapshot:
    name: str
    data: bytes
    sha256: str

    @property
    def size(self) -> int:
        return len(self.data)


def _sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _asset_name(value: object) -> str:
    if (
        type(value) is not str
        or not ASSET_NAME.fullmatch(value)
        or value in {".", ".."}
        or value.endswith(".")
    ):
        raise ValueError(f"release asset name is not a canonical leaf path: {value!r}")
    return value


def _require_directory(path: Path, label: str) -> Path:
    path = path.absolute()
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is missing or inaccessible") from exc
    if not stat.S_ISDIR(mode):
        raise ValueError(f"{label} must be a real directory, not a symlink")
    return path.resolve(strict=True)


def _snapshot_file(path: Path, label: str) -> _FileSnapshot:
    source = path.absolute()
    try:
        mode = source.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is missing or inaccessible") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a regular file, not a symlink or directory")
    try:
        with source.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if before.st_size > MAX_FILE:
                raise ValueError(f"{label} exceeds the file size limit")
            chunks: list[bytes] = []
            total = 0
            while chunk := handle.read(READ_CHUNK):
                total += len(chunk)
                if total > MAX_FILE:
                    raise ValueError(f"{label} exceeds the file size limit")
                chunks.append(chunk)
            data = b"".join(chunks)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise ValueError(f"cannot snapshot {label}") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(data) != before.st_size:
        raise ValueError(f"{label} changed while it was being snapshotted")
    return _FileSnapshot(source.name, data, _sha256_bytes(data))


def _snapshot_candidate(candidate_dir: Path) -> dict[str, _FileSnapshot]:
    root = _require_directory(candidate_dir, "candidate directory")
    entries = list(root.iterdir())
    if not entries or len(entries) > MAX_FILES:
        raise ValueError("candidate directory has an unsafe file count")
    snapshots: dict[str, _FileSnapshot] = {}
    for path in entries:
        name = _asset_name(path.name)
        if name in snapshots:
            raise ValueError("candidate directory contains duplicate asset names")
        snapshots[name] = _snapshot_file(path, f"release asset {name}")
    return snapshots


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _load_canonical_object(snapshot: _FileSnapshot, label: str) -> dict:
    data = snapshot.data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    if text.startswith("\ufeff"):
        raise ValueError(f"{label} must not contain a UTF-8 BOM")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not strict JSON: {exc}") from exc
    if type(value) is not dict:
        raise ValueError(f"{label} root must be a JSON object")
    if data != canonical_bytes(value):
        raise ValueError(f"{label} is not canonical JSON")
    return value


def _strict_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(
            _strict_equal(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _strict_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def _digest(value: object, label: str) -> str:
    if type(value) is not str or not SHA256.fullmatch(value):
        raise ValueError(
            f"{label} must be sha256 followed by 64 lowercase hex characters"
        )
    return value


def _git(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot execute git: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise ValueError(detail)
    return result.stdout.strip()


def _git_raw(repo: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *arguments],
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        raise ValueError(f"cannot execute git: {exc}") from exc
    if result.returncode != 0:
        detail = (
            result.stderr.decode("utf-8", errors="replace").strip()
            or result.stdout.decode("utf-8", errors="replace").strip()
            or "git command failed"
        )
        raise ValueError(detail)
    return result.stdout


def _tag_object_header(repo: Path, object_sha: str, expected_name: str) -> dict:
    raw_bytes = _git_raw(repo, "cat-file", "tag", object_sha)
    framing = b"tag " + str(len(raw_bytes)).encode("ascii") + b"\x00" + raw_bytes
    actual_sha = hashlib.sha1(framing, usedforsecurity=False).hexdigest()
    if actual_sha != object_sha:
        raise ValueError("annotated tag bytes do not match the captured object SHA")
    if b"\r" in raw_bytes or b"\x00" in raw_bytes:
        raise ValueError("annotated tag object contains forbidden header bytes")
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("annotated tag object is not UTF-8") from exc
    header, separator, _message = raw.partition("\n\n")
    lines = header.split("\n")
    if not separator or len(lines) != 4:
        raise ValueError(
            "annotated tag object must have exactly four canonical headers"
        )
    object_line, type_line, tag_line, tagger_line = lines
    if not object_line.startswith("object "):
        raise ValueError("annotated tag object header is missing its target")
    target_sha = object_line.removeprefix("object ")
    if not SHA.fullmatch(target_sha):
        raise ValueError("annotated tag target must be a 40-character commit SHA")
    if type_line != "type commit":
        raise ValueError("annotated version tag must target a commit directly")
    if tag_line != f"tag {expected_name}":
        raise ValueError("annotated tag internal name does not match its exact ref")
    if not TAGGER.fullmatch(tagger_line):
        raise ValueError("annotated tag has a malformed tagger header")
    return {
        "internal_name": tag_line.removeprefix("tag "),
        "tagger": tagger_line.removeprefix("tagger "),
        "target_sha": target_sha,
        "target_type": "commit",
    }


def _annotated_tag_identity(repo: Path, version: str) -> dict:
    repo = _require_directory(repo, "Git repository")
    if not is_semver(version):
        raise ValueError(f"candidate version is not SemVer: {version!r}")
    if _git(repo, "rev-parse", "--is-inside-work-tree") != "true":
        raise ValueError("tag repository is not a Git work tree")
    name = f"v{version}"
    ref = f"refs/tags/{name}"
    if _git(repo, "for-each-ref", "--format=%(symref)", ref):
        raise ValueError("annotated version tag ref must not be a symbolic alias")
    object_sha = _git(repo, "show-ref", "--verify", "--hash", ref)
    if not SHA.fullmatch(object_sha):
        raise ValueError("tag object ID must be a 40-character lowercase Git SHA")
    object_type = _git(repo, "cat-file", "-t", object_sha)
    if object_type != "tag":
        raise ValueError(
            f"{name} is a lightweight tag; an annotated tag object is required"
        )
    header = _tag_object_header(repo, object_sha, name)
    peeled_commit = _git(repo, "rev-parse", "--verify", f"{object_sha}^{{commit}}")
    if not SHA.fullmatch(peeled_commit):
        raise ValueError("peeled tag commit must be a 40-character lowercase Git SHA")
    if peeled_commit != header["target_sha"]:
        raise ValueError("annotated tag target and peeled commit disagree")
    if _git(repo, "show-ref", "--verify", "--hash", ref) != object_sha:
        raise ValueError("annotated tag ref changed while its identity was captured")
    if _git(repo, "for-each-ref", "--format=%(symref)", ref):
        raise ValueError("annotated version tag ref became a symbolic alias")
    return {
        **header,
        "name": name,
        "object_sha": object_sha,
        "peeled_commit": peeled_commit,
    }


def _materialize_candidate(
    snapshots: dict[str, _FileSnapshot], destination: Path
) -> None:
    for name, snapshot in snapshots.items():
        path = destination / name
        with path.open("xb") as handle:
            handle.write(snapshot.data)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)


def _release_assets(snapshots: dict[str, _FileSnapshot], manifest: dict) -> list[dict]:
    payload = manifest.get("payload")
    if type(payload) is not list:
        raise ValueError("candidate payload must be an array")
    names: list[str] = []
    for entry in payload:
        if type(entry) is not dict or set(entry) != {"name", "sha256", "size"}:
            raise ValueError("candidate payload entry schema mismatch")
        names.append(_asset_name(entry["name"]))
    names.extend((MANIFEST_NAME, CHECKSUMS_NAME))
    if len(names) != len(set(names)):
        raise ValueError("release asset inventory contains duplicate names")
    if set(snapshots) != set(names):
        raise ValueError(
            "release asset inventory mismatch: "
            f"expected {sorted(names)!r}, got {sorted(snapshots)!r}"
        )
    assets: list[dict] = []
    for name in sorted(names):
        snapshot = snapshots[name]
        if not snapshot.data:
            raise ValueError(f"release asset is empty: {name}")
        assets.append({"name": name, "sha256": snapshot.sha256, "size": snapshot.size})
    return assets


def build_qualification_index(
    *,
    git_repo: Path,
    candidate_dir: Path,
    verified_authorization: external_authorization.VerifiedAuthorization,
) -> dict:
    """Build an eligibility index from immutable candidate/auth snapshots."""

    verified = external_authorization.require_verified_authorization(
        verified_authorization
    )
    snapshots = _snapshot_candidate(candidate_dir)
    if MANIFEST_NAME not in snapshots or "image-provenance.json" not in snapshots:
        raise ValueError("candidate directory lacks required authority documents")
    manifest_snapshot = snapshots[MANIFEST_NAME]
    provenance_snapshot = snapshots["image-provenance.json"]
    manifest_json = _load_canonical_object(manifest_snapshot, "candidate manifest")
    provenance_json = _load_canonical_object(
        provenance_snapshot, "OCI detached provenance"
    )

    with tempfile.TemporaryDirectory(prefix="tomorrowci-candidate-snapshot-") as temp:
        snapshot_dir = Path(temp)
        snapshot_dir.chmod(0o700)
        _materialize_candidate(snapshots, snapshot_dir)
        manifest = candidate_manifest.verify_candidate(dist=snapshot_dir)
        if not _strict_equal(manifest_json, manifest):
            raise ValueError(
                "candidate verifier result disagrees with candidate manifest bytes"
            )
        version = manifest.get("version")
        source = manifest.get("source")
        workflow = manifest.get("workflow")
        if type(version) is not str or not is_semver(version):
            raise ValueError("candidate version must be strict SemVer")
        if type(source) is not dict or type(source.get("commit")) is not str:
            raise ValueError("candidate source identity is malformed")
        if type(workflow) is not dict:
            raise ValueError("candidate workflow identity is malformed")
        source_sha = source["commit"]
        if not SHA.fullmatch(source_sha):
            raise ValueError("candidate source SHA must be 40 lowercase hex characters")

        verified_provenance = oci_candidate.verify_candidate(
            archive=snapshot_dir / "tomorrowci-oci-linux-amd64.tar",
            metadata=snapshot_dir / "build-metadata.json",
            containerfile=snapshot_dir / "Containerfile",
            provenance=snapshot_dir / "image-provenance.json",
            expected_source_sha=source_sha,
            expected_repository=source.get("repository"),
            expected_run_id=str(workflow["run_id"]),
            expected_run_attempt=workflow["run_attempt"],
        )
    if not _strict_equal(provenance_json, verified_provenance):
        raise ValueError("OCI verifier result disagrees with detached provenance bytes")
    if provenance_json.get("version") != version:
        raise ValueError("OCI provenance version does not match candidate version")
    oci = provenance_json.get("oci")
    if type(oci) is not dict or type(oci.get("manifest")) is not dict:
        raise ValueError("OCI provenance manifest identity is malformed")
    manifest_digest = _digest(
        oci["manifest"].get("digest"), "OCI image manifest digest"
    )

    if (
        manifest_snapshot.sha256 != verified.candidate_manifest_sha256
        or provenance_snapshot.sha256 != verified.oci_provenance_sha256
        or manifest_digest != verified.oci_manifest_digest
        or source_sha != verified.candidate_commit
        or source.get("repository") != verified.candidate_repository
        or version != verified.candidate_version
        or workflow.get("run_id") != verified.candidate_run_id
        or workflow.get("run_attempt") != verified.candidate_run_attempt
    ):
        raise ValueError(
            "candidate inputs do not match the complete external authorization receipt"
        )

    tag = _annotated_tag_identity(git_repo, version)
    if tag["peeled_commit"] != source_sha:
        raise ValueError(
            "annotated tag peeled commit does not match candidate source SHA"
        )

    return {
        "candidate": {
            "manifest_sha256": manifest_snapshot.sha256,
            "source_sha": source_sha,
            "version": version,
        },
        "external_authorization": verified.stable_identity(),
        "kind": KIND,
        "oci": {
            "manifest_sha256": manifest_digest,
            "provenance_sha256": provenance_snapshot.sha256,
        },
        "release_assets": _release_assets(snapshots, manifest),
        "schema_version": 1,
        "status": STATUS,
        "tag": tag,
    }


def verify_qualification_index(
    *,
    attestation: Path,
    git_repo: Path,
    candidate_dir: Path,
    verified_authorization: external_authorization.VerifiedAuthorization,
) -> dict:
    attestation_snapshot = _snapshot_file(
        attestation, "tag promotion qualification index"
    )
    document = _load_canonical_object(
        attestation_snapshot, "tag promotion qualification index"
    )
    expected = build_qualification_index(
        git_repo=git_repo,
        candidate_dir=candidate_dir,
        verified_authorization=verified_authorization,
    )
    if not _strict_equal(document, expected):
        raise ValueError(
            "tag promotion qualification index does not match exact verified inputs"
        )
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--git-repo", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verified = external_authorization.verify_authorization(
            authorization=args.authorization,
            signature=args.signature,
            policy=args.policy,
            expected_policy_sha256=args.expected_policy_sha256,
            allowed_signers=args.allowed_signers,
            candidate_manifest=args.candidate_dir / MANIFEST_NAME,
            oci_provenance=args.candidate_dir / "image-provenance.json",
            evidence=args.evidence,
        )
        document = verify_qualification_index(
            attestation=args.attestation,
            git_repo=args.git_repo,
            candidate_dir=args.candidate_dir,
            verified_authorization=verified,
        )
    except (
        KeyError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"tag-promotion-attestation: FAIL: {exc}", file=sys.stderr)
        return 1
    digest = _sha256_bytes(canonical_bytes(document))
    print(f"tag-promotion-attestation: PASS: {STATUS}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
