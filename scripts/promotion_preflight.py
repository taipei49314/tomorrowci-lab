#!/usr/bin/env python3
"""Fail-closed state and read-back helpers for exact-byte release promotion.

The protected workflow owns mutation sequencing.  This module validates
immutable snapshots, exact retry states, and non-clobber boundaries.  It keeps
the GHCR tag write and final Release publish refused because the documented
mutation APIs lack the required create-only or compare-and-swap preconditions.
"""

from __future__ import annotations

import argparse
import hashlib
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
PUBLICATION_KIND = "tomorrowci.protected-exact-byte-publication-plan.v1"
DISABLED_STATUS = "PREPARED_ONLY_NOT_STANDALONE_PUBLISH_AUTHORITY"
ORAS_TOOL = (
    "ghcr.io/oras-project/oras@"
    "sha256:a3ce6b38d4c510ea9fdc0449b942ea44fb790f157e79b5e7e30b1e7460fe5579"
)
AUTHORIZATION_FILES = {
    "external-authorization.json",
    "external-authorization.json.sig",
    "external-qualification-evidence.json",
    "preregistered-policy.json",
    "tag-promotion-attestation.json",
}
PREPARED_STATE_FILES = {
    "authorization-marker-identity.json",
    "external-authorization-receipt.json",
    "publication-plan.json",
    "release-body.md",
    "remote-state.json",
    "tag-promotion-attestation.json",
    "tracked-trust-identity.json",
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


def _snapshot(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect {label}") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise ValueError(f"{label} size changed while reading")
    return data


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _page_items(path: Path, label: str) -> list[dict]:
    value = json.loads(
        _snapshot(path, label).decode("utf-8"),
        object_pairs_hook=lambda pairs: _reject_duplicate_pairs(pairs, label),
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError(f"{label} contains non-finite JSON value {item}")
        ),
    )
    if type(value) is not list:
        raise ValueError(f"{label} must be an array of API pages")
    items: list[dict] = []
    for page in value:
        if type(page) is not list:
            raise ValueError(f"{label} page must be an array")
        for item in page:
            if type(item) is not dict:
                raise ValueError(f"{label} item must be an object")
            items.append(item)
    return items


def _load_json_array(path: Path, label: str) -> list:
    value = json.loads(
        _snapshot(path, label).decode("utf-8"),
        object_pairs_hook=lambda pairs: _reject_duplicate_pairs(pairs, label),
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError(f"{label} contains non-finite JSON value {item}")
        ),
    )
    if type(value) is not list:
        raise ValueError(f"{label} must be an array")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, object]], label: str) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"{label} contains duplicate JSON key {key!r}")
        value[key] = item
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


def inspect_repository_head(
    repository_metadata: dict,
    branch_metadata: dict,
    *,
    repository: str,
    source_sha: str,
) -> dict:
    if not SLUG.fullmatch(repository) or not SHA.fullmatch(source_sha):
        raise ValueError("expected repository or source SHA is malformed")
    branch_object = branch_metadata.get("object")
    if (
        repository_metadata.get("full_name") != repository
        or repository_metadata.get("default_branch") != "master"
        or branch_metadata.get("ref") != "refs/heads/master"
        or type(branch_object) is not dict
        or branch_object.get("type") != "commit"
        or branch_object.get("sha") != source_sha
    ):
        raise ValueError("default branch no longer names the exact source commit")
    return {"default_branch": "master", "repository": repository, "sha": source_sha}


def inspect_promotion_workflow_run(
    metadata: dict,
    *,
    repository: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
) -> dict:
    if not SLUG.fullmatch(repository) or not SHA.fullmatch(source_sha):
        raise ValueError("expected promotion repository or source SHA is malformed")
    expected_id = _positive(run_id, "promotion run ID")
    expected_attempt = _positive(run_attempt, "promotion run attempt")
    expected = {
        "event": "workflow_dispatch",
        "head_branch": "master",
        "head_sha": source_sha,
        "id": expected_id,
        "path": ".github/workflows/protected-exact-byte-promotion.yml",
        "run_attempt": expected_attempt,
        "status": "in_progress",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"promotion workflow run {key} mismatch")
    if metadata.get("conclusion") is not None:
        raise ValueError("in-progress promotion run already has a conclusion")
    repo = metadata.get("repository")
    head_repo = metadata.get("head_repository")
    actor = metadata.get("actor")
    triggering_actor = metadata.get("triggering_actor")
    if (
        type(repo) is not dict
        or type(head_repo) is not dict
        or repo.get("full_name") != repository
        or head_repo.get("full_name") != repository
        or type(actor) is not dict
        or type(actor.get("id")) is not int
        or type(triggering_actor) is not dict
        or type(triggering_actor.get("id")) is not int
    ):
        raise ValueError("promotion workflow run repository or actor identity mismatch")
    return {
        **expected,
        "actor_id": actor["id"],
        "triggering_actor_id": triggering_actor["id"],
    }


def inspect_release_environment(metadata: dict) -> dict:
    if metadata.get("name") != "release":
        raise ValueError("protected environment name mismatch")
    rules = metadata.get("protection_rules")
    if type(rules) is not list:
        raise ValueError("release environment protection rules are missing")
    reviewer_rules = [
        rule for rule in rules if rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        raise ValueError("release environment must have one required-reviewer rule")
    rule = reviewer_rules[0]
    reviewers = rule.get("reviewers")
    if (
        rule.get("prevent_self_review") is not True
        or type(reviewers) is not list
        or not reviewers
        or any(
            type(item) is not dict
            or item.get("type") not in {"User", "Team"}
            or type(item.get("reviewer")) is not dict
            or type(item["reviewer"].get("id")) is not int
            for item in reviewers
        )
    ):
        raise ValueError("release environment reviewer approval is not fail-closed")
    branch_policy = metadata.get("deployment_branch_policy")
    if (
        type(branch_policy) is not dict
        or branch_policy.get("protected_branches") is not True
        or branch_policy.get("custom_branch_policies") is not False
    ):
        raise ValueError("release environment must allow protected branches only")
    return {
        "environment": "release",
        "prevent_self_review": True,
        "required_reviewers": len(reviewers),
        "protected_branches_only": True,
    }


def inspect_approval_history(
    approvals: list,
    *,
    environment_metadata: dict,
    run_metadata: dict,
) -> dict:
    """Bind the approval identity fields exposed by the run-level REST API."""

    inspect_release_environment(environment_metadata)
    environment_id = environment_metadata.get("id")
    reviewer_rule = next(
        rule
        for rule in environment_metadata["protection_rules"]
        if rule.get("type") == "required_reviewers"
    )
    configured_reviewers = reviewer_rule["reviewers"]
    direct_user_ids = {
        item["reviewer"]["id"]
        for item in configured_reviewers
        if item.get("type") == "User"
    }
    has_team_reviewer = any(item.get("type") == "Team" for item in configured_reviewers)
    actor = run_metadata.get("actor")
    triggering_actor = run_metadata.get("triggering_actor")
    if (
        type(environment_id) is not int
        or environment_id <= 0
        or type(actor) is not dict
        or type(actor.get("id")) is not int
        or type(triggering_actor) is not dict
        or type(triggering_actor.get("id")) is not int
        or type(approvals) is not list
    ):
        raise ValueError("approval context identity is malformed")
    approvers: list[dict] = []
    for review in approvals:
        if type(review) is not dict:
            raise ValueError("approval history entry is malformed")
        environments = review.get("environments")
        if type(environments) is not list:
            raise ValueError("approval history environments are malformed")
        matches = [
            item
            for item in environments
            if type(item) is dict
            and item.get("id") == environment_id
            and item.get("name") == "release"
        ]
        if not matches:
            continue
        if (
            len(environments) != 1
            or len(matches) != 1
            or review.get("state") != "approved"
        ):
            raise ValueError("release environment review is not an exact approval")
        user = review.get("user")
        if (
            type(user) is not dict
            or type(user.get("id")) is not int
            or user["id"] <= 0
            or type(user.get("login")) is not str
            or not user["login"]
            or user["id"] in {actor["id"], triggering_actor["id"]}
            or (not has_team_reviewer and user["id"] not in direct_user_ids)
        ):
            raise ValueError("release approval identity is missing or self-approved")
        approvers.append({"id": user["id"], "login": user["login"]})
    if not approvers:
        raise ValueError("no observable independent release approval")
    identities = sorted({(item["id"], item["login"]) for item in approvers})
    return {
        "approval_history_scope": "workflow_run",
        "environment_id": environment_id,
        "reviewers": [
            {"id": reviewer_id, "login": login} for reviewer_id, login in identities
        ],
    }


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


def inspect_tracked_trust_material(
    *, allowed_signers: Path, expected_policy_digest: Path
) -> dict:
    """Snapshot the repository trust root and exact policy anchor."""

    signers = _snapshot(allowed_signers, "allowed-signers trust root")
    anchor = _snapshot(expected_policy_digest, "expected policy digest")
    try:
        anchor_text = anchor.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("expected policy digest must be ASCII") from exc
    if not anchor_text.endswith("\n") or anchor_text.count("\n") != 1:
        raise ValueError("expected policy digest must contain one LF-terminated line")
    digest = anchor_text[:-1]
    if not SHA256.fullmatch(digest):
        raise ValueError("expected policy digest is malformed")
    if not signers or b"\x00" in signers:
        raise ValueError("allowed-signers trust root is empty or binary")
    return {
        "allowed_signers_sha256": _sha256(signers),
        "expected_policy_sha256": digest,
    }


def inspect_package_pages(pages: Path, *, package_name: str, owner: str) -> str:
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,127})", package_name):
        raise ValueError("GHCR package name is malformed")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner):
        raise ValueError("GHCR owner is malformed")
    matches = []
    for package in _page_items(pages, "GitHub package API pages"):
        if package.get("name") == package_name:
            if package.get("package_type") != "container":
                raise ValueError("named GitHub package is not a container package")
            package_owner = package.get("owner")
            if type(package_owner) is not dict or package_owner.get("login") != owner:
                raise ValueError("GHCR package namespace mismatch")
            if package.get("visibility") not in {"private", "public"}:
                raise ValueError("GHCR package visibility is unsupported")
            matches.append(package)
    if len(matches) > 1:
        raise ValueError("GitHub package API contains duplicate package identity")
    if not matches:
        return "ABSENT"
    return f"PRESENT_{matches[0]['visibility'].upper()}"


def _attestation_assets(attestation: dict, candidate_dir: Path) -> list[dict]:
    if (
        attestation.get("kind") != tag_promotion_attestation.KIND
        or attestation.get("status") != tag_promotion_attestation.STATUS
        or attestation.get("schema_version") != 1
    ):
        raise ValueError("tag-promotion qualification identity mismatch")
    assets = attestation.get("release_assets")
    if type(assets) is not list or not assets:
        raise ValueError("tag-promotion release asset inventory is missing")
    expected: list[dict] = []
    names: list[str] = []
    for item in assets:
        if type(item) is not dict or set(item) != {"name", "sha256", "size"}:
            raise ValueError("tag-promotion release asset schema mismatch")
        name = item["name"]
        digest = item["sha256"]
        size = item["size"]
        if (
            type(name) is not str
            or Path(name).name != name
            or name in {".", ".."}
            or name == "tag-promotion-attestation.json"
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}", name)
            or type(digest) is not str
            or not SHA256.fullmatch(digest)
            or type(size) is not int
            or size <= 0
        ):
            raise ValueError("tag-promotion release asset identity is malformed")
        data = _snapshot(candidate_dir / name, f"candidate release asset {name}")
        if len(data) != size or _sha256(data) != digest:
            raise ValueError(f"candidate release asset bytes disagree: {name}")
        names.append(name)
        expected.append({"name": name, "sha256": digest, "size": size})
    if names != sorted(names) or len(names) != len(set(names)):
        raise ValueError("tag-promotion release asset names are not canonical")
    actual_names = sorted(entry.name for entry in candidate_dir.iterdir())
    if actual_names != names:
        raise ValueError(
            "candidate directory does not equal the release asset inventory"
        )
    return expected


def release_body(attestation: dict, *, oci_repository: str) -> str:
    candidate = attestation.get("candidate")
    external = attestation.get("external_authorization")
    authorization = external.get("authorization") if type(external) is dict else None
    oci = attestation.get("oci")
    if (
        type(candidate) is not dict
        or type(authorization) is not dict
        or type(oci) is not dict
    ):
        raise ValueError("tag-promotion authority identity is incomplete")
    version = candidate.get("version")
    source_sha = candidate.get("source_sha")
    manifest = candidate.get("manifest_sha256")
    authorization_id = authorization.get("id")
    image_digest = oci.get("manifest_sha256")
    if (
        type(version) is not str
        or not re.fullmatch(r"[0-9A-Za-z.-]+", version)
        or type(source_sha) is not str
        or not SHA.fullmatch(source_sha)
        or type(manifest) is not str
        or not SHA256.fullmatch(manifest)
        or type(authorization_id) is not str
        or not AUTHORIZATION_ID.fullmatch(authorization_id)
        or type(image_digest) is not str
        or not SHA256.fullmatch(image_digest)
        or not re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+", oci_repository)
    ):
        raise ValueError("tag-promotion release-note identity is malformed")
    return (
        f"Protected exact-byte prerelease for TomorrowCI v{version}.\n\n"
        f"- Source: `{source_sha}`\n"
        f"- Candidate manifest: `{manifest}`\n"
        f"- External authorization: `{authorization_id}`\n"
        f"- OCI image: `{oci_repository}@{image_digest}`\n\n"
        "Assets and image bytes are promoted from the verified candidate without rebuilding.\n"
    )


def inspect_release_state(
    releases: list[dict],
    *,
    tag_name: str,
    target_commitish: str,
    release_name: str,
    body: str,
    expected_assets: list[dict],
) -> dict:
    matches = [release for release in releases if release.get("tag_name") == tag_name]
    if len(matches) > 1:
        raise ValueError("GitHub Releases API contains duplicate tag identity")
    if not matches:
        return {
            "missing_assets": [item["name"] for item in expected_assets],
            "state": "CREATE_NONCLOBBER_DRAFT_PRERELEASE",
        }
    release = matches[0]
    expected_fields = {
        "name": release_name,
        "body": body,
        "tag_name": tag_name,
        "prerelease": True,
    }
    for key, value in expected_fields.items():
        if release.get(key) != value:
            raise ValueError(f"GitHub Release {key} drift")
    # GitHub may normalize target_commitish to the default branch after the tag
    # exists.  The separately verified annotated tag object is authoritative.
    if (
        type(release.get("target_commitish")) is not str
        or not release["target_commitish"]
    ):
        raise ValueError("GitHub Release target_commitish is malformed")
    if type(release.get("id")) is not int or release["id"] <= 0:
        raise ValueError("GitHub Release ID is invalid")
    observed_assets = release.get("assets")
    if type(observed_assets) is not list:
        raise ValueError("GitHub Release assets are missing")
    expected_by_name = {item["name"]: item for item in expected_assets}
    seen: set[str] = set()
    for asset in observed_assets:
        if type(asset) is not dict or type(asset.get("name")) is not str:
            raise ValueError("GitHub Release asset metadata is malformed")
        name = asset["name"]
        if name in seen or name not in expected_by_name:
            raise ValueError("GitHub Release contains duplicate or unexpected asset")
        seen.add(name)
        expected = expected_by_name[name]
        if (
            asset.get("size") != expected["size"]
            or asset.get("digest") != expected["sha256"]
        ):
            raise ValueError(f"GitHub Release asset bytes drift: {name}")
    missing = sorted(set(expected_by_name) - seen)
    draft = release.get("draft")
    immutable = release.get("immutable")
    if draft is True and immutable is False:
        return {
            "missing_assets": missing,
            "release_id": release["id"],
            "state": "RESUME_EXACT_NONCLOBBER_DRAFT" if missing else "DRAFT_COMPLETE",
        }
    if draft is False and immutable is True and not missing:
        return {
            "missing_assets": [],
            "release_id": release["id"],
            "state": "IDEMPOTENT_EXACT_IMMUTABLE_PRERELEASE",
        }
    raise ValueError("GitHub Release is neither an exact draft nor immutable release")


def inspect_immutable_release_setting(metadata: dict) -> None:
    """Require the repository immutable-releases control to be explicitly enabled."""

    if type(metadata) is not dict or metadata.get("enabled") is not True:
        raise ValueError("repository immutable releases are not enabled")


def inspect_ghcr_state(
    versions: list[dict], *, image_tag: str, manifest_digest: str
) -> dict:
    if not re.fullmatch(r"v[0-9A-Za-z.-]+", image_tag) or not SHA256.fullmatch(
        manifest_digest
    ):
        raise ValueError("expected GHCR tag or digest is malformed")
    tagged_digest: str | None = None
    digest_present = False
    if len(versions) > 1:
        raise ValueError("GHCR repository contains unexpected additional versions")
    for version in versions:
        name = version.get("name")
        metadata = version.get("metadata")
        container = metadata.get("container") if type(metadata) is dict else None
        if (
            type(name) is not str
            or not SHA256.fullmatch(name)
            or type(metadata) is not dict
            or metadata.get("package_type") != "container"
            or type(container) is not dict
            or type(container.get("tags")) is not list
            or any(type(tag) is not str for tag in container["tags"])
        ):
            raise ValueError("GHCR package version metadata is malformed")
        if name != manifest_digest or any(
            tag != image_tag for tag in container["tags"]
        ):
            raise ValueError("GHCR repository contains an unrelated digest or tag")
        if name == manifest_digest:
            digest_present = True
        if image_tag in container["tags"]:
            if tagged_digest is not None:
                raise ValueError("GHCR tag appears on multiple manifest digests")
            tagged_digest = name
    if tagged_digest is not None and tagged_digest != manifest_digest:
        raise ValueError("GHCR tag already names a different manifest digest")
    if tagged_digest == manifest_digest:
        state = "IDEMPOTENT_EXACT_IMAGE"
    elif digest_present:
        state = "READY_TO_ADD_EXACT_TAG"
    else:
        state = "READY_FOR_EXACT_OCI_COPY"
    return {"manifest_digest": manifest_digest, "state": state, "tag": image_tag}


def inspect_public_asset_readback(directory: Path, expected_assets: list[dict]) -> None:
    actual = sorted(entry.name for entry in directory.iterdir())
    expected = [item["name"] for item in expected_assets]
    if actual != expected:
        raise ValueError("public release download inventory mismatch")
    for item in expected_assets:
        data = _snapshot(
            directory / item["name"], f"downloaded release asset {item['name']}"
        )
        if len(data) != item["size"] or _sha256(data) != item["sha256"]:
            raise ValueError(f"public release asset read-back mismatch: {item['name']}")


def inspect_public_oci_descriptor(descriptor: Path, expected_digest: str) -> dict:
    if not SHA256.fullmatch(expected_digest):
        raise ValueError("expected public OCI digest is malformed")
    value = _load_json(descriptor, "public OCI descriptor")
    if set(value) != {"digest", "mediaType", "size"}:
        raise ValueError("public OCI descriptor schema mismatch")
    if (
        value["digest"] != expected_digest
        or value["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
        or type(value["size"]) is not int
        or value["size"] <= 0
    ):
        raise ValueError("public OCI descriptor identity mismatch")
    return value


def inspect_http_etag(headers: Path) -> str:
    raw = _snapshot(headers, "HTTP response headers")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("HTTP response headers are not ASCII") from exc
    values = []
    for line in text.replace("\r\n", "\n").split("\n"):
        name, separator, value = line.partition(":")
        if separator and name.lower() == "etag":
            values.append(value.strip())
    if len(values) != 1 or not re.fullmatch(
        r'(?:W/)?"[A-Za-z0-9._~:/+=-]{1,200}"', values[0]
    ):
        raise ValueError("HTTP response has no single safe ETag")
    return values[0]


def inspect_doctor_output(output: Path, *, expected_version: str) -> dict:
    if not re.fullmatch(r"[0-9A-Za-z.-]+", expected_version):
        raise ValueError("expected doctor version is malformed")
    try:
        lines = _snapshot(output, "doctor output").decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("doctor output is not UTF-8") from exc
    if not lines or lines[0] != "TomorrowCI doctor":
        raise ValueError("doctor output header mismatch")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.startswith("note: "):
            continue
        key, separator, value = line.partition(": ")
        if not separator or key in fields:
            raise ValueError("doctor output contains malformed or duplicate fields")
        fields[key] = value
    required = {
        "docker",
        "host_execution_of_targets",
        "podman",
        "security_defaults",
        "selected_engine",
        "status",
        "tool_version",
    }
    if set(fields) != required:
        raise ValueError("doctor output field inventory mismatch")
    if (
        fields["tool_version"] != expected_version
        or fields["docker"] not in {"true", "false"}
        or fields["podman"] not in {"true", "false"}
        or fields["security_defaults"] != "OK"
        or fields["host_execution_of_targets"] != "FORBIDDEN by default"
    ):
        raise ValueError("doctor identity or security semantics mismatch")
    ready = fields["status"] == "READY"
    blocked = fields["status"] == "BLOCKED for container execution"
    selected = fields["selected_engine"]
    if ready:
        if selected not in {"Docker", "Podman"}:
            raise ValueError("READY doctor output has no selected engine")
        if fields[selected.lower()] != "true":
            raise ValueError("READY doctor output contradicts engine detection")
    elif blocked:
        if (
            selected != "NONE (sandbox BLOCKED)"
            or fields["docker"] != "false"
            or fields["podman"] != "false"
        ):
            raise ValueError("BLOCKED doctor output is not honest about engines")
    else:
        raise ValueError("doctor status is neither READY nor honest BLOCKED")
    return {"selected_engine": selected, "status": fields["status"]}


def build_publication_plan(
    *,
    attestation_path: Path,
    candidate_dir: Path,
    remote_state_path: Path,
    marker_identity_path: Path,
    release_pages_path: Path,
    ghcr_versions_path: Path,
    repository: str,
) -> tuple[dict, str]:
    """Build a read-only exact-byte plan; never grant mutation authority."""

    if not SLUG.fullmatch(repository):
        raise ValueError("publication repository is malformed")
    attestation = _load_json(attestation_path, "tag-promotion qualification index")
    assets = _attestation_assets(attestation, candidate_dir)
    attestation_bytes = _snapshot(attestation_path, "tag-promotion attestation")
    supplemental_assets = [
        {
            "name": "tag-promotion-attestation.json",
            "sha256": _sha256(attestation_bytes),
            "size": len(attestation_bytes),
        }
    ]
    release_assets = sorted(assets + supplemental_assets, key=lambda item: item["name"])
    candidate = attestation.get("candidate")
    external = attestation.get("external_authorization")
    authorization = external.get("authorization") if type(external) is dict else None
    tag = attestation.get("tag")
    oci = attestation.get("oci")
    if not all(type(item) is dict for item in (candidate, authorization, tag, oci)):
        raise ValueError("tag-promotion publication identity is incomplete")
    version = candidate.get("version")
    source_sha = candidate.get("source_sha")
    authorization_id = authorization.get("id")
    tag_oid = tag.get("object_sha")
    manifest_digest = oci.get("manifest_sha256")
    if (
        type(version) is not str
        or not re.fullmatch(r"[0-9A-Za-z.-]+", version)
        or type(source_sha) is not str
        or not SHA.fullmatch(source_sha)
        or type(authorization_id) is not str
        or not AUTHORIZATION_ID.fullmatch(authorization_id)
        or type(tag_oid) is not str
        or not SHA.fullmatch(tag_oid)
        or type(manifest_digest) is not str
        or not SHA256.fullmatch(manifest_digest)
    ):
        raise ValueError("tag-promotion publication identity is malformed")
    tag_name = f"v{version}"
    version_ref = f"refs/tags/{tag_name}"
    marker_ref = f"refs/tags/tomorrowci-authorization/{authorization_id}"
    if (
        tag.get("name") != tag_name
        or tag.get("internal_name") != tag_name
        or tag.get("peeled_commit") != source_sha
    ):
        raise ValueError("annotated version tag does not bind candidate identity")
    marker = _load_json(marker_identity_path, "authorization marker identity")
    marker_oid = marker.get("object_sha")
    if (
        type(marker_oid) is not str
        or not SHA.fullmatch(marker_oid)
        or marker.get("name") != f"tomorrowci-authorization/{authorization_id}"
        or marker.get("internal_name") != marker.get("name")
        or marker.get("peeled_commit") != source_sha
    ):
        raise ValueError("authorization marker does not bind candidate identity")
    remote = _load_json(remote_state_path, "promotion remote state")
    expected_refs = {marker_ref: marker_oid, version_ref: tag_oid}
    if (
        remote.get("kind") != KIND
        or remote.get("schema_version") != 1
        or remote.get("status") != DISABLED_STATUS
        or remote.get("state")
        not in {"READY_FOR_ATOMIC_CREATE_ONLY", "IDEMPOTENT_EXACT_PAIR"}
        or remote.get("refs")
        != {key: expected_refs[key] for key in sorted(expected_refs)}
    ):
        raise ValueError(
            "promotion remote ref state disagrees with exact annotated refs"
        )
    owner = repository.split("/", 1)[0].lower()
    oci_repository = f"ghcr.io/{owner}/tomorrowci"
    body = release_body(attestation, oci_repository=oci_repository)
    release = inspect_release_state(
        _page_items(release_pages_path, "GitHub Releases API pages"),
        tag_name=tag_name,
        target_commitish=source_sha,
        release_name=f"TomorrowCI {tag_name}",
        body=body,
        expected_assets=release_assets,
    )
    ghcr = inspect_ghcr_state(
        _page_items(ghcr_versions_path, "GHCR package-version API pages"),
        image_tag=tag_name,
        manifest_digest=manifest_digest,
    )
    plan = {
        "candidate": {
            "assets": assets,
            "source_sha": source_sha,
            "version": version,
        },
        "ghcr": {
            **ghcr,
            "repository": oci_repository,
            "source_archive": "tomorrowci-oci-linux-amd64.tar",
            "source_reference": f"v{version}-{source_sha}",
            "tool": ORAS_TOOL,
        },
        "kind": PUBLICATION_KIND,
        "mutation": {
            "plan_is_standalone_authority": False,
            "protected_roll_forward": True,
        },
        "refs": {
            "atomic": True,
            "force": False,
            "identity": {key: expected_refs[key] for key in sorted(expected_refs)},
            "state": remote["state"],
        },
        "release": {
            **release,
            "assets": release_assets,
            "draft": True,
            "name": f"TomorrowCI {tag_name}",
            "prerelease": True,
            "tag_name": tag_name,
            "target_commitish": source_sha,
        },
        "schema_version": 1,
        "status": DISABLED_STATUS,
    }
    return plan, body


def _safe_extract_exact_zip(
    archive: Path, destination: Path, *, expected_files: set[str], label: str
) -> None:
    destination = destination.absolute()
    if destination.exists():
        raise ValueError(f"{label} extraction destination already exists")
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or set(names) != expected_files:
            raise ValueError(f"{label} bundle inventory mismatch")
        if sum(entry.file_size for entry in entries) > 64 * 1024 * 1024:
            raise ValueError(f"{label} bundle exceeds size limit")
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
                raise ValueError(f"unsafe {label} bundle entry: {name!r}")
            data = package.read(entry)
            if len(data) != entry.file_size:
                raise ValueError(f"{label} entry size drift: {name}")
            with (destination / name).open("xb") as handle:
                handle.write(data)


def safe_extract_authorization(archive: Path, destination: Path) -> None:
    _safe_extract_exact_zip(
        archive,
        destination,
        expected_files=AUTHORIZATION_FILES,
        label="authorization",
    )


def safe_extract_prepared_state(archive: Path, destination: Path) -> None:
    _safe_extract_exact_zip(
        archive,
        destination,
        expected_files=PREPARED_STATE_FILES,
        label="prepared state",
    )


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
        if (
            len(fields) != 2
            or not SHA.fullmatch(fields[0])
            or fields[1] not in expected
        ):
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


def refuse_unconditional_ghcr_tag_write() -> None:
    raise ValueError(
        "GHCR publication is disabled: the registry tag PUT used by ORAS has no "
        "proven create-only/If-None-Match primitive, so a concurrent tag cannot be "
        "updated without clobber risk"
    )


def refuse_unconditional_release_publish() -> None:
    raise ValueError(
        "GitHub Release publication is disabled: the documented release PATCH "
        "endpoint has no conditional If-Match primitive, so a validated draft "
        "cannot be published without a final concurrent-update window"
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
    repository_head = commands.add_parser("inspect-repository-head")
    repository_head.add_argument("--repository-metadata", type=Path, required=True)
    repository_head.add_argument("--branch-metadata", type=Path, required=True)
    repository_head.add_argument("--repository", required=True)
    repository_head.add_argument("--source-sha", required=True)
    workflow_run = commands.add_parser("inspect-promotion-run")
    workflow_run.add_argument("--metadata", type=Path, required=True)
    workflow_run.add_argument("--repository", required=True)
    workflow_run.add_argument("--source-sha", required=True)
    workflow_run.add_argument("--run-id", required=True)
    workflow_run.add_argument("--run-attempt", required=True)
    artifact = commands.add_parser("inspect-authorization-artifact")
    artifact.add_argument("--metadata", type=Path, required=True)
    artifact.add_argument("--artifact-id", required=True)
    artifact.add_argument("--artifact-sha256", required=True)
    environment = commands.add_parser("inspect-release-environment")
    environment.add_argument("--metadata", type=Path, required=True)
    approval = commands.add_parser("inspect-approval-history")
    approval.add_argument("--approvals", type=Path, required=True)
    approval.add_argument("--environment", type=Path, required=True)
    approval.add_argument("--run-metadata", type=Path, required=True)
    extract = commands.add_parser("extract-authorization")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    state_extract = commands.add_parser("extract-prepared-state")
    state_extract.add_argument("--archive", type=Path, required=True)
    state_extract.add_argument("--destination", type=Path, required=True)
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
    trust = commands.add_parser("inspect-trust-material")
    trust.add_argument("--allowed-signers", type=Path, required=True)
    trust.add_argument("--expected-policy-digest", type=Path, required=True)
    packages = commands.add_parser("inspect-package-pages")
    packages.add_argument("--pages", type=Path, required=True)
    packages.add_argument("--package-name", required=True)
    packages.add_argument("--owner", required=True)
    immutable = commands.add_parser("inspect-immutable-release-setting")
    immutable.add_argument("--metadata", type=Path, required=True)
    ghcr = commands.add_parser("inspect-ghcr-pages")
    ghcr.add_argument("--pages", type=Path, required=True)
    ghcr.add_argument("--image-tag", required=True)
    ghcr.add_argument("--manifest-digest", required=True)
    ghcr.add_argument("--required-state")
    plan = commands.add_parser("build-publication-plan")
    plan.add_argument("--attestation", type=Path, required=True)
    plan.add_argument("--candidate-dir", type=Path, required=True)
    plan.add_argument("--remote-state", type=Path, required=True)
    plan.add_argument("--marker-identity", type=Path, required=True)
    plan.add_argument("--release-pages", type=Path, required=True)
    plan.add_argument("--ghcr-versions", type=Path, required=True)
    plan.add_argument("--repository", required=True)
    plan.add_argument("--release-body-output", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    readback = commands.add_parser("verify-public-assets")
    readback.add_argument("--plan", type=Path, required=True)
    readback.add_argument("--directory", type=Path, required=True)
    candidate_readback = commands.add_parser("verify-candidate-assets")
    candidate_readback.add_argument("--plan", type=Path, required=True)
    candidate_readback.add_argument("--directory", type=Path, required=True)
    public_oci = commands.add_parser("inspect-public-oci-descriptor")
    public_oci.add_argument("--descriptor", type=Path, required=True)
    public_oci.add_argument("--expected-digest", required=True)
    etag = commands.add_parser("inspect-http-etag")
    etag.add_argument("--headers", type=Path, required=True)
    doctor = commands.add_parser("inspect-doctor-output")
    doctor.add_argument("--output", type=Path, required=True)
    doctor.add_argument("--expected-version", required=True)
    commands.add_parser("assert-ghcr-nonclobber-write")
    commands.add_parser("assert-release-publish-nonclobber")
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
        elif args.command == "inspect-repository-head":
            value = inspect_repository_head(
                _load_json(args.repository_metadata, "repository metadata"),
                _load_json(args.branch_metadata, "default branch metadata"),
                repository=args.repository,
                source_sha=args.source_sha,
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-promotion-run":
            value = inspect_promotion_workflow_run(
                _load_json(args.metadata, "promotion run metadata"),
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
        elif args.command == "inspect-release-environment":
            value = inspect_release_environment(
                _load_json(args.metadata, "release environment metadata")
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-approval-history":
            value = inspect_approval_history(
                _load_json_array(args.approvals, "approval history"),
                environment_metadata=_load_json(
                    args.environment, "release environment metadata"
                ),
                run_metadata=_load_json(args.run_metadata, "promotion run metadata"),
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "extract-authorization":
            safe_extract_authorization(args.archive, args.destination)
            print("authorization bundle: PASS")
        elif args.command == "extract-prepared-state":
            safe_extract_prepared_state(args.archive, args.destination)
            print("prepared state bundle: PASS")
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
            digest = inspect_oci_manifest_digest(args.provenance, args.expected_digest)
            print(f"OCI authoritative manifest digest: PASS: {digest}")
        elif args.command == "inspect-trust-material":
            value = inspect_tracked_trust_material(
                allowed_signers=args.allowed_signers,
                expected_policy_digest=args.expected_policy_digest,
            )
            sys.stdout.buffer.write(canonical_bytes(value))
        elif args.command == "inspect-package-pages":
            print(
                inspect_package_pages(
                    args.pages, package_name=args.package_name, owner=args.owner
                )
            )
        elif args.command == "inspect-immutable-release-setting":
            inspect_immutable_release_setting(
                _load_json(args.metadata, "immutable-release setting")
            )
            print("repository immutable releases: PASS")
        elif args.command == "inspect-ghcr-pages":
            value = inspect_ghcr_state(
                _page_items(args.pages, "GHCR package-version API pages"),
                image_tag=args.image_tag,
                manifest_digest=args.manifest_digest,
            )
            if (
                args.required_state is not None
                and value["state"] != args.required_state
            ):
                raise ValueError("GHCR state does not equal the required exact state")
            print(json.dumps(value, sort_keys=True))
        elif args.command == "build-publication-plan":
            value, body = build_publication_plan(
                attestation_path=args.attestation,
                candidate_dir=args.candidate_dir,
                remote_state_path=args.remote_state,
                marker_identity_path=args.marker_identity,
                release_pages_path=args.release_pages,
                ghcr_versions_path=args.ghcr_versions,
                repository=args.repository,
            )
            with args.output.open("xb") as handle:
                handle.write(canonical_bytes(value))
            with args.release_body_output.open(
                "x", encoding="utf-8", newline="\n"
            ) as handle:
                handle.write(body)
            print("exact-byte publication plan: PASS: protected roll-forward only")
        elif args.command in {"verify-public-assets", "verify-candidate-assets"}:
            value = _load_json(args.plan, "exact-byte publication plan")
            candidate = value.get("candidate")
            release = value.get("release")
            if (
                value.get("kind") != PUBLICATION_KIND
                or value.get("status") != DISABLED_STATUS
                or type(candidate) is not dict
                or type(candidate.get("assets")) is not list
                or type(release) is not dict
                or type(release.get("assets")) is not list
            ):
                raise ValueError("exact-byte publication plan identity mismatch")
            expected = (
                release["assets"]
                if args.command == "verify-public-assets"
                else candidate["assets"]
            )
            inspect_public_asset_readback(args.directory, expected)
            print(f"{args.command}: PASS")
        elif args.command == "inspect-public-oci-descriptor":
            value = inspect_public_oci_descriptor(args.descriptor, args.expected_digest)
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-http-etag":
            print(inspect_http_etag(args.headers))
        elif args.command == "inspect-doctor-output":
            value = inspect_doctor_output(
                args.output, expected_version=args.expected_version
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "assert-ghcr-nonclobber-write":
            refuse_unconditional_ghcr_tag_write()
        elif args.command == "assert-release-publish-nonclobber":
            refuse_unconditional_release_publish()
        else:
            raise ValueError("unhandled promotion-preflight command")
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"promotion-preflight: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
