#!/usr/bin/env python3
"""Verify one detached independent authorization without publishing anything.

Every security-sensitive input is read exactly once into an immutable byte
snapshot.  Digests, JSON validation, semantic checks, and SSH verification all
use those same bytes; source paths are never reopened after snapshotting.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from version_contract import is_semver

AUTH_KIND = "tomorrowci.external-authorization.v1"
POLICY_KIND = "tomorrowci.external-authorization-policy.v1"
EVIDENCE_KIND = "tomorrowci.external-qualification-evidence.v1"
RECEIPT_KIND = "tomorrowci.external-authorization-verification-receipt.v1"
RECEIPT_STATUS = "VERIFIED_ONLY_NOT_CONSUMED_OR_PUBLISH_AUTHORITY"
NAMESPACE = "tomorrowci-release-v1"
DECISION = "authorize_exact_candidate"
QUALIFICATION_CHECKS = {
    "candidate_image_pull",
    "live_core",
    "live_dependency",
    "live_runtime",
    "socket_doctor",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,199}$")
AUTH_ID = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_SECURITY_INPUT = 64 * 1024 * 1024
_CAPABILITY = object()


@dataclass(frozen=True)
class _Snapshot:
    label: str
    source: Path
    data: bytes
    sha256: str


@dataclass(frozen=True)
class VerifiedAuthorization:
    """In-process capability produced only after the complete verifier passes."""

    authorization_id: str
    authorization_sha256: str
    signature_sha256: str
    policy_sha256: str
    allowed_signers_sha256: str
    evidence_sha256: str
    candidate_manifest_sha256: str
    oci_provenance_sha256: str
    candidate_repository: str
    candidate_commit: str
    candidate_version: str
    candidate_run_id: int
    candidate_run_attempt: int
    oci_manifest_digest: str
    external_repository: str
    external_commit: str
    external_run_id: int
    external_run_attempt: int
    auditor_principal: str
    verified_at: str
    _capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._capability is not _CAPABILITY:
            raise ValueError(
                "VerifiedAuthorization can only be created by the external verifier"
            )

    def stable_identity(self) -> dict:
        """Return the time-independent identity safe to embed in promotion data."""

        return {
            "authorization": {
                "id": self.authorization_id,
                "sha256": self.authorization_sha256,
                "signature_sha256": self.signature_sha256,
            },
            "candidate": {
                "commit": self.candidate_commit,
                "manifest_sha256": self.candidate_manifest_sha256,
                "oci_manifest_digest": self.oci_manifest_digest,
                "oci_provenance_sha256": self.oci_provenance_sha256,
                "repository": self.candidate_repository,
                "run_attempt": self.candidate_run_attempt,
                "run_id": self.candidate_run_id,
                "version": self.candidate_version,
            },
            "evidence_sha256": self.evidence_sha256,
            "external": {
                "commit": self.external_commit,
                "repository": self.external_repository,
                "run_attempt": self.external_run_attempt,
                "run_id": self.external_run_id,
            },
            "kind": RECEIPT_KIND,
            "policy_sha256": self.policy_sha256,
            "schema_version": 1,
            "status": RECEIPT_STATUS,
            "trust": {
                "allowed_signers_sha256": self.allowed_signers_sha256,
                "auditor_principal": self.auditor_principal,
                "namespace": NAMESPACE,
            },
        }

    def receipt(self) -> dict:
        """Return the stable identity plus this CLI/function observation time."""

        return {**self.stable_identity(), "verified_at": self.verified_at}


def require_verified_authorization(value: object) -> VerifiedAuthorization:
    if type(value) is not VerifiedAuthorization or value._capability is not _CAPABILITY:
        raise ValueError(
            "a VerifiedAuthorization capability from the complete external verifier is required"
        )
    return value


def _digest_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _snapshot(path: Path, label: str) -> _Snapshot:
    """Read a regular file once and retain the exact bytes for all later checks."""

    source = path.absolute()
    try:
        mode = source.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is missing or inaccessible") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    try:
        with source.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if before.st_size > MAX_SECURITY_INPUT:
                raise ValueError(f"{label} exceeds the input size limit")
            data = handle.read(MAX_SECURITY_INPUT + 1)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise ValueError(f"cannot snapshot {label}") from exc
    if len(data) > MAX_SECURITY_INPUT:
        raise ValueError(f"{label} exceeds the input size limit")
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
    return _Snapshot(label, source, data, _digest_bytes(data))


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(snapshot: _Snapshot, *, canonical: bool = True) -> dict:
    try:
        value = json.loads(
            snapshot.data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value: {value}")
            ),
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{snapshot.label} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{snapshot.label} is not strict JSON: {exc}") from exc
    if type(value) is not dict:
        raise ValueError(f"{snapshot.label} root must be an object")
    if canonical and snapshot.data != _canonical_bytes(value):
        raise ValueError(f"{snapshot.label} is not canonical JSON")
    return value


def _object(value: object, keys: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise ValueError(f"{label} has an unexpected schema")
    return value


def _text(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _time(value: object, label: str) -> datetime:
    if type(value) is not str or not TIMESTAMP.fullmatch(value):
        raise ValueError(f"{label} must be canonical UTC seconds")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError(f"invalid {label}")
    return parsed


def _verification_clock(now: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if now is None else now
    if type(current) is not datetime or current.tzinfo is None:
        raise ValueError("verification clock must be an aware datetime")
    return current.astimezone(timezone.utc)


def _validate_candidate(value: object, label: str) -> dict:
    candidate = _object(
        value,
        {
            "commit",
            "manifest_sha256",
            "oci_manifest_digest",
            "oci_provenance_sha256",
            "ref",
            "repository",
            "run_attempt",
            "run_id",
            "version",
        },
        label,
    )
    _text(candidate["repository"], SLUG, f"{label} repository")
    _text(candidate["commit"], SHA, f"{label} commit")
    if candidate["ref"] != "refs/heads/master":
        raise ValueError(f"{label} ref must be refs/heads/master")
    if type(candidate["version"]) is not str or not is_semver(candidate["version"]):
        raise ValueError(f"invalid {label} version")
    _positive(candidate["run_id"], f"{label} run ID")
    _positive(candidate["run_attempt"], f"{label} run attempt")
    for name in (
        "manifest_sha256",
        "oci_manifest_digest",
        "oci_provenance_sha256",
    ):
        _text(candidate[name], SHA256, f"{label} {name}")
    return candidate


def _validate_external(value: object, label: str, *, authorization: bool) -> dict:
    keys = {
        "artifact_name",
        "auditor_principal",
        "authorization_id",
        "commit",
        "engine_name",
        "repository",
        "run_attempt",
        "run_id",
        "workflow_path",
    }
    if authorization:
        keys |= {"run_url", "workflow_ref"}
    external = _object(value, keys, label)
    repository = _text(external["repository"], SLUG, f"{label} repository")
    commit = _text(external["commit"], SHA, f"{label} commit")
    workflow_path = _text(
        external["workflow_path"], WORKFLOW_PATH, f"{label} workflow path"
    )
    _text(external["auditor_principal"], TOKEN, f"{label} auditor principal")
    _text(external["authorization_id"], AUTH_ID, f"{label} authorization ID")
    _text(external["artifact_name"], TOKEN, f"{label} artifact name")
    if external["engine_name"] not in ("docker", "podman"):
        raise ValueError(f"{label} engine must be docker or podman")
    run_id = _positive(external["run_id"], f"{label} run ID")
    run_attempt = _positive(external["run_attempt"], f"{label} run attempt")
    if authorization:
        expected_ref = f"{repository}/{workflow_path}@{commit}"
        if external["workflow_ref"] != expected_ref:
            raise ValueError("external workflow ref is not pinned to the exact commit")
        expected_url = (
            f"https://github.com/{repository}/actions/runs/{run_id}"
            f"/attempts/{run_attempt}"
        )
        if external["run_url"] != expected_url:
            raise ValueError(
                "external run URL does not match the exact run and attempt"
            )
    return external


def _load_policy(snapshot: _Snapshot) -> dict:
    policy = _load_json(snapshot)
    _object(
        policy,
        {"candidate", "external", "kind", "schema_version", "trust", "validity"},
        "authorization policy",
    )
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 1
        or policy["kind"] != POLICY_KIND
    ):
        raise ValueError("authorization policy identity mismatch")
    _validate_candidate(policy["candidate"], "policy candidate")
    _validate_external(policy["external"], "policy external", authorization=False)
    trust = _object(
        policy["trust"], {"allowed_signers_sha256", "namespace"}, "policy trust"
    )
    if trust["namespace"] != NAMESPACE:
        raise ValueError("policy SSH signature namespace mismatch")
    _text(trust["allowed_signers_sha256"], SHA256, "allowed signers digest")
    validity = _object(
        policy["validity"], {"not_after", "not_before"}, "policy validity"
    )
    valid_from = _time(validity["not_before"], "policy not_before")
    valid_until = _time(validity["not_after"], "policy not_after")
    if valid_from >= valid_until:
        raise ValueError("policy validity window is empty")
    if valid_until - valid_from > timedelta(days=7):
        raise ValueError("policy validity window exceeds seven days")
    return policy


def _load_authorization(snapshot: _Snapshot) -> dict:
    authorization = _load_json(snapshot)
    _object(
        authorization,
        {
            "auditor",
            "candidate",
            "decision",
            "evidence",
            "expires_at",
            "external",
            "issued_at",
            "kind",
            "schema_version",
        },
        "external authorization",
    )
    if (
        type(authorization["schema_version"]) is not int
        or authorization["schema_version"] != 1
        or authorization["kind"] != AUTH_KIND
        or authorization["decision"] != DECISION
    ):
        raise ValueError("external authorization identity or decision mismatch")
    _validate_candidate(authorization["candidate"], "authorized candidate")
    _validate_external(
        authorization["external"], "authorized external run", authorization=True
    )
    auditor = _object(authorization["auditor"], {"principal"}, "authorization auditor")
    _text(auditor["principal"], TOKEN, "authorization auditor principal")
    evidence = _object(
        authorization["evidence"],
        {"engine", "image_digest", "name", "sha256", "size"},
        "authorization evidence",
    )
    _text(evidence["name"], TOKEN, "evidence name")
    _text(evidence["sha256"], SHA256, "evidence digest")
    _text(evidence["image_digest"], SHA256, "evidence image digest")
    _positive(evidence["size"], "evidence size")
    engine = _object(evidence["engine"], {"name", "version"}, "evidence engine")
    if engine["name"] not in ("docker", "podman"):
        raise ValueError("evidence engine must be docker or podman")
    _text(engine["version"], TOKEN, "evidence engine version")
    issued = _time(authorization["issued_at"], "authorization issued_at")
    expires = _time(authorization["expires_at"], "authorization expires_at")
    if issued >= expires:
        raise ValueError("authorization validity window is empty")
    if expires - issued > timedelta(hours=24):
        raise ValueError("authorization validity window exceeds 24 hours")
    return authorization


def _load_evidence(snapshot: _Snapshot) -> dict:
    evidence = _load_json(snapshot)
    _object(
        evidence,
        {
            "artifact_name",
            "candidate",
            "engine",
            "external",
            "kind",
            "qualification",
            "schema_version",
            "status",
        },
        "external qualification evidence",
    )
    if (
        type(evidence["schema_version"]) is not int
        or evidence["schema_version"] != 1
        or evidence["kind"] != EVIDENCE_KIND
        or evidence["status"] != "PASS"
    ):
        raise ValueError("external qualification evidence identity mismatch")
    _text(evidence["artifact_name"], TOKEN, "evidence artifact name")
    candidate = _object(evidence["candidate"], {"image_digest"}, "evidence candidate")
    _text(candidate["image_digest"], SHA256, "evidence candidate image digest")
    engine = _object(evidence["engine"], {"name", "version"}, "evidence engine")
    if engine["name"] not in ("docker", "podman"):
        raise ValueError("evidence engine must be docker or podman")
    _text(engine["version"], TOKEN, "evidence engine version")
    external = _object(
        evidence["external"],
        {
            "commit",
            "conclusion",
            "repository",
            "run_attempt",
            "run_id",
            "run_url",
            "workflow_path",
            "workflow_ref",
        },
        "evidence external run",
    )
    repository = _text(external["repository"], SLUG, "evidence repository")
    commit = _text(external["commit"], SHA, "evidence commit")
    workflow_path = _text(
        external["workflow_path"], WORKFLOW_PATH, "evidence workflow path"
    )
    run_id = _positive(external["run_id"], "evidence run ID")
    run_attempt = _positive(external["run_attempt"], "evidence run attempt")
    if external["conclusion"] != "success":
        raise ValueError("external qualification evidence conclusion must be success")
    if external["workflow_ref"] != f"{repository}/{workflow_path}@{commit}":
        raise ValueError("evidence workflow ref is not pinned to the exact commit")
    expected_url = (
        f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
    )
    if external["run_url"] != expected_url:
        raise ValueError("evidence run URL does not match the exact run and attempt")
    qualification = _object(
        evidence["qualification"], {"checks", "result"}, "evidence qualification"
    )
    checks = _object(
        qualification["checks"], QUALIFICATION_CHECKS, "evidence qualification checks"
    )
    if qualification["result"] != "PASS" or any(
        value != "PASS" for value in checks.values()
    ):
        raise ValueError("every external qualification result must be PASS")
    return evidence


def _validate_candidate_manifest(snapshot: _Snapshot, expected: dict) -> None:
    manifest = _load_json(snapshot, canonical=False)
    _object(
        manifest,
        {
            "build",
            "kind",
            "payload",
            "promotion",
            "schema_version",
            "source",
            "status",
            "version",
            "workflow",
        },
        "candidate manifest",
    )
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["kind"] != "tomorrowci.release-candidate.v1"
        or manifest["status"] != "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED"
    ):
        raise ValueError("candidate manifest identity mismatch")
    source = _object(
        manifest["source"], {"commit", "dirty", "ref", "repository"}, "candidate source"
    )
    workflow = _object(
        manifest["workflow"],
        {"name", "run_attempt", "run_id", "run_url", "workflow_ref"},
        "candidate workflow",
    )
    promotion = _object(
        manifest["promotion"],
        {"authorization_source", "authorized", "instruction"},
        "candidate promotion",
    )
    if (
        source
        != {
            "commit": expected["commit"],
            "dirty": False,
            "ref": expected["ref"],
            "repository": expected["repository"],
        }
        or manifest["version"] != expected["version"]
        or workflow["name"] != "release-candidate"
        or workflow["run_id"] != expected["run_id"]
        or workflow["run_attempt"] != expected["run_attempt"]
        or workflow["workflow_ref"]
        != f"{expected['repository']}/.github/workflows/candidate.yml@{expected['ref']}"
        or workflow["run_url"]
        != (
            f"https://github.com/{expected['repository']}/actions/runs/"
            f"{expected['run_id']}/attempts/{expected['run_attempt']}"
        )
        or promotion["authorized"] is not False
        or promotion["authorization_source"] is not None
        or type(promotion["instruction"]) is not str
    ):
        raise ValueError("candidate manifest identity does not match policy")
    build = _object(
        manifest["build"], {"reproducible_builds", "rust_toolchain"}, "candidate build"
    )
    if build["reproducible_builds"] != 2 or type(build["rust_toolchain"]) is not str:
        raise ValueError("candidate build contract mismatch")
    payload = manifest["payload"]
    if type(payload) is not list or not payload:
        raise ValueError("candidate payload must be a nonempty array")
    names: list[str] = []
    for entry in payload:
        item = _object(entry, {"name", "sha256", "size"}, "candidate payload entry")
        names.append(_text(item["name"], TOKEN, "candidate payload name"))
        _text(item["sha256"], SHA256, "candidate payload digest")
        _positive(item["size"], "candidate payload size")
    if len(names) != len(set(names)):
        raise ValueError("candidate payload contains duplicate names")


def _validate_oci_provenance(snapshot: _Snapshot, expected: dict) -> None:
    provenance = _load_json(snapshot, canonical=False)
    _object(
        provenance,
        {
            "build",
            "kind",
            "oci",
            "promotion",
            "schema_version",
            "source",
            "status",
            "version",
            "workflow",
        },
        "OCI provenance",
    )
    if (
        type(provenance["schema_version"]) is not int
        or provenance["schema_version"] != 1
        or provenance["kind"] != "tomorrowci.oci-candidate-provenance.v1"
        or provenance["status"] != "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED"
        or provenance["version"] != expected["version"]
    ):
        raise ValueError("OCI provenance identity mismatch")
    source = _object(
        provenance["source"], {"commit", "repository", "url"}, "OCI provenance source"
    )
    workflow = _object(
        provenance["workflow"], {"run_attempt", "run_id", "run_url"}, "OCI workflow"
    )
    promotion = _object(
        provenance["promotion"],
        {"authorization_source", "authorized", "instruction"},
        "OCI promotion",
    )
    oci = provenance["oci"]
    if type(oci) is not dict or type(oci.get("manifest")) is not dict:
        raise ValueError("OCI provenance manifest schema mismatch")
    if (
        source
        != {
            "commit": expected["commit"],
            "repository": expected["repository"],
            "url": f"https://github.com/{expected['repository']}",
        }
        or workflow["run_id"] != expected["run_id"]
        or workflow["run_attempt"] != expected["run_attempt"]
        or workflow["run_url"]
        != (
            f"https://github.com/{expected['repository']}/actions/runs/"
            f"{expected['run_id']}/attempts/{expected['run_attempt']}"
        )
        or oci["manifest"].get("digest") != expected["oci_manifest_digest"]
        or promotion["authorized"] is not False
        or promotion["authorization_source"] is not None
        or type(promotion["instruction"]) is not str
        or type(provenance["build"]) is not dict
    ):
        raise ValueError("OCI provenance identity does not match policy")


def _validate_allowed_signers(snapshot: _Snapshot, principal: str, digest: str) -> None:
    if snapshot.sha256 != digest:
        raise ValueError("allowed signers trust root digest mismatch")
    try:
        lines = snapshot.data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("allowed signers trust root is not UTF-8") from exc
    records = [line.split() for line in lines if line and not line.startswith("#")]
    if len(records) != 1 or len(records[0]) not in (3, 4):
        raise ValueError("allowed signers must contain exactly one unoptioned key")
    record = records[0]
    if record[0] != principal or record[1] != "ssh-ed25519":
        raise ValueError("allowed signers principal does not match policy")
    try:
        base64.b64decode(record[2], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("allowed signers key is not canonical base64") from exc


def _write_private_snapshot(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        path.chmod(0o600)
    except OSError as exc:
        raise ValueError("cannot protect SSH verifier snapshot") from exc
    return path


def _verify_signature(
    *,
    authorization: _Snapshot,
    signature: _Snapshot,
    allowed_signers: _Snapshot,
    principal: str,
    ssh_keygen: str,
) -> None:
    executable = shutil.which(ssh_keygen)
    if executable is None:
        raise ValueError(
            "ssh-keygen is unavailable; signature verification fails closed"
        )
    with tempfile.TemporaryDirectory(prefix="tomorrowci-sshsig-") as temporary:
        directory = Path(temporary)
        try:
            directory.chmod(0o700)
        except OSError as exc:
            raise ValueError("cannot protect SSH verifier directory") from exc
        root = _write_private_snapshot(
            directory, "allowed_signers", allowed_signers.data
        )
        sig = _write_private_snapshot(directory, "authorization.sig", signature.data)
        completed = subprocess.run(
            [
                executable,
                "-Y",
                "verify",
                "-f",
                str(root),
                "-I",
                principal,
                "-n",
                NAMESPACE,
                "-s",
                str(sig),
            ],
            input=authorization.data,
            capture_output=True,
            check=False,
            timeout=30,
        )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"detached SSH signature verification failed: {detail}")


def verify_authorization(
    *,
    authorization: Path,
    signature: Path,
    policy: Path,
    policy_signature: Path,
    allowed_signers: Path,
    candidate_manifest: Path,
    oci_provenance: Path,
    evidence: Path,
    now: datetime | None = None,
    ssh_keygen: str = "ssh-keygen",
) -> VerifiedAuthorization:
    # Snapshot every input before interpreting any of them.  No source path is
    # reopened after this point.
    policy_snapshot = _snapshot(policy, "authorization policy")
    policy_signature_snapshot = _snapshot(
        policy_signature, "authorization policy detached SSH signature"
    )
    authorization_snapshot = _snapshot(authorization, "external authorization")
    signature_snapshot = _snapshot(signature, "detached SSH signature")
    allowed_snapshot = _snapshot(allowed_signers, "allowed signers trust root")
    manifest_snapshot = _snapshot(candidate_manifest, "candidate manifest")
    provenance_snapshot = _snapshot(oci_provenance, "OCI provenance")
    evidence_snapshot = _snapshot(evidence, "external qualification evidence")

    policy_value = _load_policy(policy_snapshot)
    auth = _load_authorization(authorization_snapshot)
    policy_candidate = policy_value["candidate"]
    policy_external = policy_value["external"]
    if auth["candidate"] != policy_candidate:
        raise ValueError("authorization candidate does not match preregistered policy")
    auth_external = auth["external"]
    if {key: auth_external[key] for key in policy_external} != policy_external:
        raise ValueError(
            "authorization external run does not match preregistered policy"
        )
    if auth["auditor"]["principal"] != policy_external["auditor_principal"]:
        raise ValueError("authorization auditor does not match preregistered identity")
    if auth["evidence"]["name"] != policy_external["artifact_name"]:
        raise ValueError("authorization evidence name mismatch")
    if auth["evidence"]["engine"]["name"] != policy_external["engine_name"]:
        raise ValueError("authorization engine mismatch")

    candidate_repo = policy_candidate["repository"]
    external_repo = policy_external["repository"]
    if candidate_repo.casefold() == external_repo.casefold():
        raise ValueError(
            "external repository must differ from the candidate repository"
        )
    if (
        candidate_repo.split("/", 1)[0].casefold()
        == external_repo.split("/", 1)[0].casefold()
    ):
        raise ValueError("external repository owner must be independent")

    if manifest_snapshot.sha256 != policy_candidate["manifest_sha256"]:
        raise ValueError("candidate manifest digest mismatch")
    if provenance_snapshot.sha256 != policy_candidate["oci_provenance_sha256"]:
        raise ValueError("OCI provenance digest mismatch")
    if (
        evidence_snapshot.sha256 != auth["evidence"]["sha256"]
        or len(evidence_snapshot.data) != auth["evidence"]["size"]
    ):
        raise ValueError("external evidence bytes do not match authorization")
    if auth["evidence"]["image_digest"] != policy_candidate["oci_manifest_digest"]:
        raise ValueError(
            "external evidence image does not match candidate OCI manifest"
        )

    _validate_candidate_manifest(manifest_snapshot, policy_candidate)
    _validate_oci_provenance(provenance_snapshot, policy_candidate)
    evidence_value = _load_evidence(evidence_snapshot)
    evidence_external = evidence_value["external"]
    expected_evidence_external = {
        "commit": auth_external["commit"],
        "conclusion": "success",
        "repository": auth_external["repository"],
        "run_attempt": auth_external["run_attempt"],
        "run_id": auth_external["run_id"],
        "run_url": auth_external["run_url"],
        "workflow_path": auth_external["workflow_path"],
        "workflow_ref": auth_external["workflow_ref"],
    }
    if evidence_external != expected_evidence_external:
        raise ValueError("evidence external run does not match signed authorization")
    if (
        evidence_value["artifact_name"] != auth["evidence"]["name"]
        or evidence_value["engine"] != auth["evidence"]["engine"]
        or evidence_value["candidate"]["image_digest"]
        != auth["evidence"]["image_digest"]
    ):
        raise ValueError("evidence identity does not match signed authorization")

    current = _verification_clock(now)
    issued = _time(auth["issued_at"], "authorization issued_at")
    expires = _time(auth["expires_at"], "authorization expires_at")
    valid_from = _time(policy_value["validity"]["not_before"], "policy not_before")
    valid_until = _time(policy_value["validity"]["not_after"], "policy not_after")
    if issued < valid_from or expires > valid_until:
        raise ValueError("authorization is outside the preregistered validity window")
    if current < issued or current >= expires:
        raise ValueError("authorization is not currently valid")

    trust = policy_value["trust"]
    _validate_allowed_signers(
        allowed_snapshot,
        policy_external["auditor_principal"],
        trust["allowed_signers_sha256"],
    )
    _verify_signature(
        authorization=policy_snapshot,
        signature=policy_signature_snapshot,
        allowed_signers=allowed_snapshot,
        principal=policy_external["auditor_principal"],
        ssh_keygen=ssh_keygen,
    )
    _verify_signature(
        authorization=authorization_snapshot,
        signature=signature_snapshot,
        allowed_signers=allowed_snapshot,
        principal=policy_external["auditor_principal"],
        ssh_keygen=ssh_keygen,
    )
    return VerifiedAuthorization(
        authorization_id=policy_external["authorization_id"],
        authorization_sha256=authorization_snapshot.sha256,
        signature_sha256=signature_snapshot.sha256,
        policy_sha256=policy_snapshot.sha256,
        allowed_signers_sha256=allowed_snapshot.sha256,
        evidence_sha256=evidence_snapshot.sha256,
        candidate_manifest_sha256=manifest_snapshot.sha256,
        oci_provenance_sha256=provenance_snapshot.sha256,
        candidate_repository=policy_candidate["repository"],
        candidate_commit=policy_candidate["commit"],
        candidate_version=policy_candidate["version"],
        candidate_run_id=policy_candidate["run_id"],
        candidate_run_attempt=policy_candidate["run_attempt"],
        oci_manifest_digest=policy_candidate["oci_manifest_digest"],
        external_repository=policy_external["repository"],
        external_commit=policy_external["commit"],
        external_run_id=policy_external["run_id"],
        external_run_attempt=policy_external["run_attempt"],
        auditor_principal=policy_external["auditor_principal"],
        verified_at=current.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        _capability=_CAPABILITY,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-signature", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--oci-provenance", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verified = verify_authorization(**vars(args))
        sys.stdout.buffer.write(_canonical_bytes(verified.receipt()))
    except (
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"external-authorization: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
