#!/usr/bin/env python3

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
from pathlib import Path, PurePosixPath

import candidate_manifest
import oci_candidate
import package_release

CAPTURE_KIND = "tomorrowci.platform-capture/v1"
RECORD_KIND = "tomorrowci.platform-qualification/v1"
STATUS = "OBSERVED_PROJECT_OWNED_ONLY"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
INTEGER = re.compile(r"^[1-9][0-9]*$")
RUN_ID = re.compile(r"^[0-9a-f]{12}$")
CONTEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
IMAGE_DIGEST = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}$")
MAX_METADATA_FILE = 4 * 1024 * 1024

CAPTURE_INPUTS = (
    "doctor.txt",
    "engine-context.txt",
    "engine-info.json",
    "engine-version.txt",
    "post-state.json",
    "pre-state.json",
    "provider-status.json",
    "replay-1.txt",
    "replay-2.txt",
    "scan.txt",
    "source-after.json",
    "source-before.json",
    "trust.txt",
)
CAPTURE_NAME = "platform-capture.json"
RECORD_NAME = "platform-record.json"


@dataclass(frozen=True)
class Platform:
    runner_os: str
    runner_arch: str
    target: str
    archive_extension: str
    binary_name: str
    provider: str
    engine_context: str
    server_architectures: tuple[str, ...]


PLATFORMS = {
    "windows-x86_64-docker-desktop-linux": Platform(
        runner_os="Windows",
        runner_arch="X64",
        target="x86_64-pc-windows-msvc",
        archive_extension="zip",
        binary_name="tomorrowci.exe",
        provider="docker-desktop-linux",
        engine_context="desktop-linux",
        server_architectures=("amd64", "x86_64"),
    ),
    "macos-x86_64-colima": Platform(
        runner_os="macOS",
        runner_arch="X64",
        target="x86_64-apple-darwin",
        archive_extension="tar.gz",
        binary_name="tomorrowci",
        provider="colima",
        engine_context="colima",
        server_architectures=("amd64", "x86_64"),
    ),
    "macos-aarch64-colima": Platform(
        runner_os="macOS",
        runner_arch="ARM64",
        target="aarch64-apple-darwin",
        archive_extension="tar.gz",
        binary_name="tomorrowci",
        provider="colima",
        engine_context="colima",
        server_architectures=("aarch64", "arm64"),
    ),
}


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(
    path: Path, label: str, *, canonical: bool = False
) -> tuple[object, bytes]:
    data = _snapshot_file(path, label, MAX_METADATA_FILE)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not strict UTF-8 JSON: {error}") from error
    if canonical and data != canonical_json_bytes(value):
        raise ValueError(f"{label} is not canonical sorted JSON")
    return value, data


def _plain_directory(path: Path, label: str) -> Path:
    absolute = path.absolute()
    _reject_alias_ancestors(absolute, label)
    try:
        before = os.lstat(absolute)
    except OSError as error:
        raise ValueError(f"{label} cannot be inspected: {error}") from error
    if not stat.S_ISDIR(before.st_mode) or _is_reparse(before):
        raise ValueError(f"{label} must be a plain directory")
    resolved = absolute.resolve(strict=True)
    after = os.stat(resolved, follow_symlinks=False)
    if not stat.S_ISDIR(after.st_mode) or _identity(before) != _identity(after):
        raise ValueError(f"{label} changed identity while being inspected")
    return resolved


def _temporary_directory(
    *, prefix: str, parent: Path, label: str
) -> tempfile.TemporaryDirectory[str]:
    """Create a temporary directory below an already verified plain parent."""
    plain_parent = _plain_directory(parent, f"{label} parent")
    return tempfile.TemporaryDirectory(prefix=prefix, dir=plain_parent)


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _reject_alias_ancestors(path: Path, label: str) -> None:
    absolute = path.absolute()
    parts = absolute.parts
    if not parts:
        raise ValueError(f"{label} has no absolute path components")
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except OSError as error:
            raise ValueError(
                f"{label} ancestor cannot be inspected: {current}: {error}"
            ) from error
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise ValueError(f"{label} ancestor aliases are forbidden: {current}")


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _file_version(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _snapshot_file(path: Path, label: str, maximum: int | None = None) -> bytes:
    absolute = path.absolute()
    _reject_alias_ancestors(absolute, label)
    try:
        before = os.lstat(absolute)
    except OSError as error:
        raise ValueError(f"{label} cannot be inspected: {error}") from error
    if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
        raise ValueError(f"{label} must be a plain regular file")
    if maximum is not None and before.st_size > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(absolute, flags)
    try:
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened) or _file_version(
            before
        ) != _file_version(opened):
            raise ValueError(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if maximum is not None and observed > maximum:
                raise ValueError(f"{label} exceeds {maximum} bytes")
            chunks.append(chunk)
        final = os.fstat(descriptor)
        if (
            _identity(opened) != _identity(final)
            or _file_version(opened) != _file_version(final)
            or final.st_size != observed
        ):
            raise ValueError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    try:
        current = os.lstat(absolute)
    except OSError as error:
        raise ValueError(f"{label} disappeared after it was read: {error}") from error
    if _identity(before) != _identity(current) or _file_version(
        before
    ) != _file_version(current):
        raise ValueError(f"{label} changed identity while it was read")
    return b"".join(chunks)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _file_record(
    path: Path, label: str, maximum: int | None = None
) -> dict[str, object]:
    data = _snapshot_file(path, label, maximum)
    return {"name": path.name, "sha256": _sha256(data), "size": len(data)}


def _write_new(path: Path, value: object, label: str) -> None:
    parent = _plain_directory(path.parent, f"{label} parent")
    output = parent / path.name
    if output.parent != parent or output.name in ("", ".", ".."):
        raise ValueError(f"{label} output path is invalid")
    data = canonical_json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
        current = os.fstat(descriptor)
        if current.st_size != len(data):
            raise ValueError(f"{label} write was incomplete")
    finally:
        os.close(descriptor)
    if _snapshot_file(output, label, len(data)) != data:
        raise ValueError(f"{label} read-back differs from written bytes")


def _component(relative: PurePosixPath) -> None:
    text = relative.as_posix()
    if (
        text in ("", ".")
        or text.startswith("/")
        or "\\" in text
        or "\0" in text
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        raise ValueError(f"non-canonical tree path: {text!r}")


def tree_snapshot(root: Path, *, exclude_internal: bool) -> dict[str, object]:
    base = _plain_directory(root, "tree root")
    entries: list[tuple[str, bytes]] = []
    casefolded: set[str] = set()

    def visit(directory: Path, parts: tuple[str, ...]) -> None:
        try:
            children = sorted(
                os.scandir(directory), key=lambda entry: entry.name.encode("utf-8")
            )
        except OSError as error:
            raise ValueError(
                f"tree directory cannot be read: {directory}: {error}"
            ) from error
        for child in children:
            if not parts and exclude_internal and child.name == ".tomorrowci":
                continue
            relative = PurePosixPath(*parts, child.name)
            _component(relative)
            folded = relative.as_posix().casefold()
            if folded in casefolded:
                raise ValueError(f"case-insensitive tree path collision: {relative}")
            info = child.stat(follow_symlinks=False)
            if _is_reparse(info) or child.is_symlink():
                raise ValueError(f"tree aliases are forbidden: {relative}")
            if stat.S_ISDIR(info.st_mode):
                casefolded.add(folded)
                visit(Path(child.path), (*parts, child.name))
            elif stat.S_ISREG(info.st_mode):
                casefolded.add(folded)
                data = _snapshot_file(Path(child.path), f"tree file {relative}")
                entries.append((relative.as_posix(), data))
            else:
                raise ValueError(f"unsupported tree entry: {relative}")

    visit(base, ())
    digest = hashlib.sha256()
    files = []
    for name, data in sorted(entries, key=lambda item: item[0].encode("utf-8")):
        file_digest = hashlib.sha256(data).hexdigest()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        files.append(
            {"path": name, "sha256": f"sha256:{file_digest}", "size": len(data)}
        )
    return {
        "algorithm": "sha256-tree-v1",
        "file_count": len(files),
        "files": files,
        "sha256": "sha256:" + digest.hexdigest(),
    }


def _validate_tree_document(value: object, label: str) -> dict[str, object]:
    document = _strict_object(
        value, {"algorithm", "file_count", "files", "sha256"}, label
    )
    if document["algorithm"] != "sha256-tree-v1":
        raise ValueError(f"{label} algorithm mismatch")
    files = document["files"]
    if type(files) is not list or type(document["file_count"]) is not int:
        raise ValueError(f"{label} inventory schema mismatch")
    if document["file_count"] != len(files):
        raise ValueError(f"{label} file count mismatch")
    digest = hashlib.sha256()
    previous: bytes | None = None
    folded: set[str] = set()
    for entry in files:
        item = _strict_object(entry, {"path", "sha256", "size"}, f"{label} entry")
        if type(item["path"]) is not str:
            raise ValueError(f"{label} path must be a string")
        relative = PurePosixPath(item["path"])
        _component(relative)
        key = item["path"].encode("utf-8")
        if previous is not None and key <= previous:
            raise ValueError(f"{label} paths are not strict byte order")
        previous = key
        if item["path"].casefold() in folded:
            raise ValueError(f"{label} contains a case-insensitive path collision")
        folded.add(item["path"].casefold())
        file_digest = _digest(item["sha256"], f"{label} file digest")[7:]
        if type(item["size"]) is not int or item["size"] < 0:
            raise ValueError(f"{label} file size is invalid")
        digest.update(key)
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
    expected = "sha256:" + digest.hexdigest()
    if document["sha256"] != expected:
        raise ValueError(f"{label} aggregate digest mismatch")
    return document


def _strict_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError(f"{label} schema mismatch")
    return value


def _integer_string(value: str, label: str) -> str:
    if not INTEGER.fullmatch(value):
        raise ValueError(f"{label} must be a positive canonical integer")
    return value


def _sha(value: str, label: str) -> str:
    if not SHA.fullmatch(value):
        raise ValueError(f"{label} must be 40 lowercase hex")
    return value


def _digest(value: str, label: str) -> str:
    if not SHA256.fullmatch(value):
        raise ValueError(f"{label} must be canonical sha256")
    return value


def _line(path: Path, label: str) -> str:
    data = _snapshot_file(path, label, 8192)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} must be UTF-8") from error
    if not text.endswith("\n") or "\r" in text or "\0" in text or text.count("\n") != 1:
        raise ValueError(f"{label} must be exactly one LF-terminated line")
    value = text[:-1]
    if not value or value.strip() != value:
        raise ValueError(f"{label} line is empty or padded")
    return value


def _capture_inputs(metadata_root: Path) -> dict[str, dict[str, object]]:
    root = _plain_directory(metadata_root, "platform metadata root")
    actual = sorted(entry.name for entry in os.scandir(root))
    if actual != list(CAPTURE_INPUTS):
        raise ValueError(
            f"platform metadata inventory mismatch: expected {list(CAPTURE_INPUTS)!r}, got {actual!r}"
        )
    return {
        name: _file_record(root / name, f"platform metadata {name}", MAX_METADATA_FILE)
        for name in CAPTURE_INPUTS
    }


def create_capture(
    *,
    metadata_root: Path,
    platform_id: str,
    runner_name: str,
    runner_os: str,
    runner_arch: str,
    project_repository: str,
    project_source_sha: str,
    project_source_ref: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> dict[str, object]:
    spec = PLATFORMS.get(platform_id)
    if spec is None:
        raise ValueError("unknown platform ID")
    if not runner_name or len(runner_name) > 128 or runner_name.strip() != runner_name:
        raise ValueError("runner name is invalid")
    if runner_os != spec.runner_os or runner_arch != spec.runner_arch:
        raise ValueError("actual runner OS/architecture does not match platform ID")
    if project_source_ref != "refs/heads/master":
        raise ValueError("platform qualification must run from refs/heads/master")
    _sha(project_source_sha, "project source SHA")
    _integer_string(workflow_run_id, "workflow run ID")
    _integer_string(workflow_run_attempt, "workflow run attempt")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", project_repository):
        raise ValueError("project repository is invalid")

    files = _capture_inputs(metadata_root)
    root = _plain_directory(metadata_root, "platform metadata root")
    context = _line(root / "engine-context.txt", "engine context")
    if context != spec.engine_context:
        raise ValueError("container engine context does not match platform contract")
    version = _line(root / "engine-version.txt", "engine version")
    if not CONTEXT.fullmatch(context) or not version:
        raise ValueError("container engine identity is malformed")
    engine_info, _ = _load_json(root / "engine-info.json", "engine info")
    engine = _strict_object(
        engine_info,
        set(engine_info) if type(engine_info) is dict else set(),
        "engine info",
    )
    for key in ("OSType", "Architecture", "ServerVersion", "OperatingSystem"):
        if type(engine.get(key)) is not str or not engine[key].strip():
            raise ValueError(f"engine info lacks canonical {key}")
    if engine["OSType"] != "linux":
        raise ValueError("platform engine must use the Linux container engine")
    if version != engine["ServerVersion"]:
        raise ValueError("captured Docker server versions contradict each other")
    if engine["Architecture"] not in spec.server_architectures:
        raise ValueError("platform engine architecture mismatch")
    if (
        spec.provider == "docker-desktop-linux"
        and "Docker Desktop" not in engine["OperatingSystem"]
    ):
        raise ValueError("Windows qualification requires Docker Desktop Linux engine")
    provider_status, _ = _load_json(
        root / "provider-status.json", "provider status", canonical=True
    )
    provider_document = _strict_object(
        provider_status,
        {"docker_context"}
        if spec.provider == "docker-desktop-linux"
        else {"colima", "docker_context"},
        "provider status",
    )
    context_list = provider_document["docker_context"]
    if type(context_list) is not list or len(context_list) != 1:
        raise ValueError("provider Docker context identity must be one JSON object")
    context_status = _strict_object(
        context_list[0],
        {"Endpoints", "Metadata", "Name", "Storage", "TLSMaterial"},
        "provider Docker context identity",
    )
    endpoints = context_status["Endpoints"]
    if type(endpoints) is not dict or type(endpoints.get("docker")) is not dict:
        raise ValueError("provider Docker context lacks its Docker endpoint")
    docker_endpoint = endpoints["docker"]
    endpoint_host = docker_endpoint.get("Host")
    if (
        context_status["Name"] != spec.engine_context
        or type(endpoint_host) is not str
        or not endpoint_host
        or docker_endpoint.get("SkipTLSVerify") is not False
    ):
        raise ValueError("provider Docker context endpoint identity mismatch")
    if spec.provider == "docker-desktop-linux":
        metadata = context_status["Metadata"]
        if (
            type(metadata) is not dict
            or metadata.get("Description") != "Docker Desktop"
        ):
            raise ValueError("Docker Desktop context description is not authoritative")
        if (
            not endpoint_host.lower().startswith("npipe:")
            or "dockerdesktoplinuxengine" not in endpoint_host.lower()
        ):
            raise ValueError("Docker Desktop Linux context endpoint identity mismatch")
        provider_identity = {
            "description": "Docker Desktop",
            "endpoint_host": endpoint_host,
            "name": "desktop-linux",
        }
    else:
        colima = _strict_object(
            provider_document["colima"],
            set(provider_document["colima"])
            if type(provider_document["colima"]) is dict
            else set(),
            "Colima status",
        )
        required_strings = (
            "arch",
            "display_name",
            "docker_socket",
            "driver",
            "runtime",
        )
        if any(
            type(colima.get(key)) is not str or not colima[key]
            for key in required_strings
        ):
            raise ValueError("Colima status lacks its required provider identity")
        if (
            colima["display_name"] != "colima"
            or colima["runtime"] != "docker"
            or colima["arch"] not in spec.server_architectures
            or not colima["docker_socket"].startswith("unix://")
            or colima["docker_socket"] != endpoint_host
        ):
            raise ValueError("Colima runtime/provider identity mismatch")
        provider_identity = {
            "arch": colima["arch"],
            "display_name": colima["display_name"],
            "docker_socket": colima["docker_socket"],
            "endpoint_host": endpoint_host,
            "driver": colima["driver"],
            "runtime": colima["runtime"],
        }
    for phase in ("pre", "post"):
        state, _ = _load_json(
            root / f"{phase}-state.json", f"engine {phase}-state", canonical=True
        )
        state = _strict_object(
            state, {"containers", "volumes"}, f"engine {phase}-state"
        )
        if state != {"containers": [], "volumes": []}:
            raise ValueError(
                f"dedicated clean-machine engine has {phase}-existing containers or volumes"
            )
    before, _ = _load_json(root / "source-before.json", "source before", canonical=True)
    after, _ = _load_json(root / "source-after.json", "source after", canonical=True)
    if before != after:
        raise ValueError("fixture source tree changed during platform qualification")
    before = _validate_tree_document(before, "source snapshot")
    for log_name in (
        "doctor.txt",
        "trust.txt",
        "scan.txt",
        "replay-1.txt",
        "replay-2.txt",
    ):
        data = _snapshot_file(root / log_name, log_name, MAX_METADATA_FILE)
        if not data or b"\0" in data:
            raise ValueError(f"{log_name} is empty or binary")
    if b"replay: PASS" not in _snapshot_file(root / "replay-1.txt", "replay 1"):
        raise ValueError("first replay log is not PASS")
    if b"replay: PASS" not in _snapshot_file(root / "replay-2.txt", "replay 2"):
        raise ValueError("second replay log is not PASS")
    if b"BLOCKED" in _snapshot_file(root / "scan.txt", "scan log"):
        raise ValueError("platform scan log contains BLOCKED")
    trust_log = _snapshot_file(root / "trust.txt", "trust log")
    if (
        not trust_log.startswith(b"TomorrowCI trust audit\n")
        or b"status: PASS" not in trust_log
    ):
        raise ValueError("platform trust audit did not report PASS")
    doctor_log = _snapshot_file(root / "doctor.txt", "doctor log")
    if (
        not doctor_log.startswith(b"TomorrowCI doctor\n")
        or b"selected_engine: Docker" not in doctor_log
        or b"status: READY" not in doctor_log
    ):
        raise ValueError("platform doctor did not report the Docker engine READY")

    return {
        "engine": {
            "architecture": engine["Architecture"],
            "command": "docker",
            "context": context,
            "operating_system": engine["OperatingSystem"],
            "os_type": engine["OSType"],
            "provider": spec.provider,
            "provider_identity": provider_identity,
            "server_version": engine["ServerVersion"],
            "version_output": version,
        },
        "files": [files[name] for name in CAPTURE_INPUTS],
        "kind": CAPTURE_KIND,
        "platform_id": platform_id,
        "runner": {
            "arch": spec.runner_arch,
            "environment": "self-hosted",
            "name": runner_name,
            "os": spec.runner_os,
        },
        "schema_version": 1,
        "source_tree": before,
        "workflow": {
            "repository": project_repository,
            "run_attempt": int(workflow_run_attempt),
            "run_id": int(workflow_run_id),
            "source_ref": project_source_ref,
            "source_sha": project_source_sha,
        },
    }


def _load_capture(
    metadata_root: Path, expected: dict[str, object]
) -> tuple[dict[str, object], bytes]:
    root = _plain_directory(metadata_root, "platform metadata root")
    actual = sorted(entry.name for entry in os.scandir(root))
    expected_names = sorted((*CAPTURE_INPUTS, CAPTURE_NAME))
    if actual != expected_names:
        raise ValueError(
            f"captured metadata inventory mismatch: expected {expected_names!r}, got {actual!r}"
        )
    value, data = _load_json(root / CAPTURE_NAME, "platform capture", canonical=True)
    if value != expected or data != canonical_json_bytes(expected):
        raise ValueError("platform capture differs from current metadata")
    return value, data


def _candidate(
    *,
    candidate_dist: Path,
    candidate_binary: Path,
    platform_id: str,
    candidate_run_id: str,
    candidate_run_attempt: str,
    candidate_manifest_sha256: str,
    candidate_source_sha: str,
    oci_manifest_digest: str,
    project_repository: str,
) -> dict[str, object]:
    spec = PLATFORMS[platform_id]
    run_id = _integer_string(candidate_run_id, "candidate run ID")
    attempt = _integer_string(candidate_run_attempt, "candidate run attempt")
    source_sha = _sha(candidate_source_sha, "candidate source SHA")
    manifest_digest = _digest(candidate_manifest_sha256, "candidate manifest digest")
    oci_digest = _digest(oci_manifest_digest, "OCI manifest digest")
    dist = _plain_directory(candidate_dist, "candidate distribution")
    manifest = candidate_manifest.verify_candidate(
        dist=dist,
        expected_source_sha=source_sha,
        expected_repository=project_repository,
        expected_run_id=run_id,
        expected_run_attempt=int(attempt),
    )
    manifest_bytes = _snapshot_file(
        dist / candidate_manifest.MANIFEST_NAME, "candidate manifest"
    )
    if _sha256(manifest_bytes) != manifest_digest:
        raise ValueError("candidate manifest digest mismatch")
    provenance = oci_candidate.verify_candidate(
        archive=dist / "tomorrowci-oci-linux-amd64.tar",
        metadata=dist / "build-metadata.json",
        containerfile=dist / "Containerfile",
        provenance=dist / "image-provenance.json",
        expected_source_sha=source_sha,
        expected_repository=project_repository,
        expected_run_id=run_id,
        expected_run_attempt=int(attempt),
    )
    if provenance["oci"]["manifest"]["digest"] != oci_digest:
        raise ValueError("OCI manifest digest differs from detached provenance")
    version = manifest["version"]
    archive_name = f"tomorrowci-v{version}-{spec.target}.{spec.archive_extension}"
    archive = dist / archive_name
    package_release.verify_archive(archive=archive, version=version, target=spec.target)
    archive_record = _file_record(archive, "platform candidate archive")
    binary_bytes = _snapshot_file(candidate_binary, "candidate platform binary")
    with _temporary_directory(
        prefix="tomorrowci-platform-archive-",
        parent=dist.parent,
        label="platform archive extraction",
    ) as raw:
        extracted = package_release.extract_archive(
            archive=archive,
            output_dir=Path(raw) / "extract",
            version=version,
            target=spec.target,
        )
        archived_binary = _snapshot_file(
            extracted / spec.binary_name, "archived candidate binary"
        )
    if binary_bytes != archived_binary:
        raise ValueError("executed platform binary differs from the candidate archive")
    completed = subprocess.run(
        [str(candidate_binary), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0 or completed.stdout.strip() != f"tomorrowci {version}":
        raise ValueError("candidate platform binary version mismatch")
    return {
        "archive": archive_record,
        "binary": {
            "name": spec.binary_name,
            "sha256": _sha256(binary_bytes),
            "size": len(binary_bytes),
        },
        "manifest_sha256": manifest_digest,
        "oci_manifest_digest": oci_digest,
        "run_attempt": int(attempt),
        "run_id": int(run_id),
        "source_sha": source_sha,
        "version": version,
    }


def _result_engine_versions(results: object, engine_version: str) -> list[str]:
    if type(results) is not list or len(results) < 2:
        raise ValueError("platform evidence must contain baseline and future results")
    if type(results[0]) is not dict or results[0].get("verdict") != "BASELINE_PASS":
        raise ValueError("platform baseline did not pass")
    forbidden = {"BLOCKED", "UNSUPPORTED", "INCONCLUSIVE", "FLAKY", "BASELINE_INVALID"}
    future_failures = []
    for result in results:
        if type(result) is not dict or result.get("verdict") in forbidden:
            raise ValueError("platform evidence contains a non-authoritative verdict")
        environment = result.get("environment")
        if (
            type(environment) is not dict
            or environment.get("engine") != "docker"
            or environment.get("engine_version") != engine_version
            or not IMAGE_DIGEST.fullmatch(str(environment.get("image_digest")))
        ):
            raise ValueError("platform result lacks exact Docker/image identity")
        if result.get("verdict") == "FUTURE_FAIL":
            future_failures.append(result["scenario_id"])
    if not future_failures:
        raise ValueError("platform fixture did not observe its required future failure")
    return future_failures


def _verify_run(
    run_root: Path,
    candidate_binary: Path,
    version: str,
    source_sha: str,
    engine_version: str,
) -> dict[str, object]:
    root = _plain_directory(run_root, "platform evidence run root")
    run_id = root.name
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("platform run ID is not canonical")
    if root.parent.name != "runs" or root.parent.parent.name != ".tomorrowci":
        raise ValueError("platform run root must be under .tomorrowci/runs")
    fixture = root.parent.parent.parent
    completed = subprocess.run(
        [str(candidate_binary), "verify", run_id],
        cwd=fixture,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0 or "verify: PASS" not in completed.stdout:
        raise ValueError(
            f"frozen platform CLI rejected evidence: {completed.stderr.strip()}"
        )
    checksums = _snapshot_file(root / "checksums.txt", "root checksums")
    if not checksums.startswith(b"# tomorrowci-checksums-v2\n"):
        raise ValueError("platform evidence is not current-v2")
    run, _ = _load_json(root / "run.json", "platform run manifest")
    manifest = _strict_object(
        run,
        {
            "baseline",
            "config_hash",
            "detection",
            "evidence_root",
            "evidence_schema_version",
            "finished_at",
            "frontier",
            "identity",
            "plan",
            "repository",
            "results",
            "run_id",
            "started_at",
            "tool_version",
        },
        "platform run manifest",
    )
    if manifest["evidence_schema_version"] != 2 or manifest["run_id"] != run_id:
        raise ValueError("platform run schema or identity mismatch")
    if manifest["tool_version"] != version:
        raise ValueError("platform evidence tool version differs from candidate")
    repository = manifest["repository"]
    if type(repository) is not dict or repository.get("commit_sha") != source_sha:
        raise ValueError(
            "platform evidence is not bound to the qualification source SHA"
        )
    identity = manifest["identity"]
    if (
        type(identity) is not dict
        or identity.get("source_commit") != source_sha
        or identity.get("dirty_tree") is not False
        or identity.get("tool_version") != version
        or identity.get("container_engine") != "docker"
    ):
        raise ValueError("platform evidence identity is incomplete or inconsistent")
    future_failures = _result_engine_versions(manifest["results"], engine_version)
    frontier = manifest["frontier"]
    if (
        type(frontier) is not dict
        or frontier.get("observed") is not True
        or frontier.get("grade") != "OBSERVED"
        or frontier.get("first_failing_scenario") != future_failures[0]
    ):
        raise ValueError("platform frontier is not the observed failure horizon")
    scenario = future_failures[0]
    replay_root = root / "scenarios" / scenario / "replays"
    names = sorted(
        entry.name for entry in os.scandir(_plain_directory(replay_root, "replay root"))
    )
    if names != ["attempt-1", "attempt-2"]:
        raise ValueError(
            "platform replay attempts must be exactly attempt-1 and attempt-2"
        )
    for name in names:
        report, _ = _load_json(
            replay_root / name / "result.json", f"{name} replay result"
        )
        if (
            type(report) is not dict
            or report.get("scenario_id") != scenario
            or report.get("ok") is not True
            or report.get("exit_match") is not True
            or report.get("signature_match") is not True
            or report.get("recorded_digest") != report.get("resolved_digest")
            or report.get("original_exit") != report.get("replay_exit")
            or report.get("original_signature") != report.get("replay_signature")
        ):
            raise ValueError(f"{name} is not an exact successful replay")
    inventory = tree_snapshot(root, exclude_internal=False)
    return {
        "checked_files": inventory["file_count"],
        "frontier": {
            "failure_signature": frontier.get("failure_signature"),
            "first_failing_scenario": scenario,
            "horizon_label": frontier.get("horizon_label"),
            "last_passing_scenario": frontier.get("last_passing_scenario"),
        },
        "root_sha256": inventory["sha256"],
        "run_id": run_id,
        "root_checksums_sha256": _sha256(checksums),
        "replay_count": 2,
    }


def build_record(args: argparse.Namespace) -> dict[str, object]:
    if args.project_source_ref != "refs/heads/master":
        raise ValueError("platform evidence must bind refs/heads/master")
    if args.candidate_source_sha != args.project_source_sha:
        raise ValueError("candidate and qualification source SHA must be identical")
    capture_expected = create_capture(
        metadata_root=args.metadata_root,
        platform_id=args.platform_id,
        runner_name=args.runner_name,
        runner_os=args.runner_os,
        runner_arch=args.runner_arch,
        project_repository=args.project_repository,
        project_source_sha=args.project_source_sha,
        project_source_ref=args.project_source_ref,
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
    )
    capture, capture_bytes = _load_capture(args.metadata_root, capture_expected)
    current_source = tree_snapshot(args.fixture_source, exclude_internal=True)
    if current_source != capture["source_tree"]:
        raise ValueError(
            "captured fixture source does not match the exact checked-out source"
        )
    candidate = _candidate(
        candidate_dist=args.candidate_dist,
        candidate_binary=args.candidate_binary,
        platform_id=args.platform_id,
        candidate_run_id=args.candidate_run_id,
        candidate_run_attempt=args.candidate_run_attempt,
        candidate_manifest_sha256=args.candidate_manifest_sha256,
        candidate_source_sha=args.candidate_source_sha,
        oci_manifest_digest=args.oci_manifest_digest,
        project_repository=args.project_repository,
    )
    evidence = _verify_run(
        args.run_root,
        args.candidate_binary,
        candidate["version"],
        args.project_source_sha,
        capture["engine"]["server_version"],
    )
    return {
        "candidate": candidate,
        "capture_sha256": _sha256(capture_bytes),
        "evidence": evidence,
        "kind": RECORD_KIND,
        "platform": {
            "engine": capture["engine"],
            "platform_id": args.platform_id,
            "runner": capture["runner"],
        },
        "schema_version": 1,
        "source_tree": capture["source_tree"],
        "status": STATUS,
        "workflow": capture["workflow"],
    }


def verify_artifact(args: argparse.Namespace) -> None:
    artifact = _plain_directory(args.artifact_root, "platform artifact root")
    actual = sorted(entry.name for entry in os.scandir(artifact))
    expected_inventory = [".tomorrowci", "metadata", RECORD_NAME]
    if actual != expected_inventory:
        raise ValueError(
            f"platform artifact inventory mismatch: expected {expected_inventory!r}, got {actual!r}"
        )
    record, record_bytes = _load_json(
        artifact / RECORD_NAME, "platform qualification record", canonical=True
    )
    document = _strict_object(
        record,
        {
            "candidate",
            "capture_sha256",
            "evidence",
            "kind",
            "platform",
            "schema_version",
            "source_tree",
            "status",
            "workflow",
        },
        "platform qualification record",
    )
    if (
        document["kind"] != RECORD_KIND
        or document["schema_version"] != 1
        or document["status"] != STATUS
    ):
        raise ValueError("platform qualification record identity mismatch")
    platform = _strict_object(
        document["platform"], {"engine", "platform_id", "runner"}, "record platform"
    )
    if platform["platform_id"] != args.platform_id:
        raise ValueError("record platform ID differs from requested platform")
    runner = _strict_object(
        platform["runner"], {"arch", "environment", "name", "os"}, "record runner"
    )
    evidence = _strict_object(
        document["evidence"],
        {
            "checked_files",
            "frontier",
            "replay_count",
            "root_checksums_sha256",
            "root_sha256",
            "run_id",
        },
        "record evidence",
    )
    run_id = evidence["run_id"]
    if type(run_id) is not str or not RUN_ID.fullmatch(run_id):
        raise ValueError("record evidence run ID is invalid")
    runs = _plain_directory(artifact / ".tomorrowci" / "runs", "artifact runs root")
    run_names = sorted(entry.name for entry in os.scandir(runs))
    if run_names != [run_id]:
        raise ValueError("platform artifact must contain exactly its recorded run")

    spec = PLATFORMS[args.platform_id]
    candidate, _ = _load_json(
        args.candidate_dist / candidate_manifest.MANIFEST_NAME,
        "candidate manifest for artifact read-back",
    )
    if type(candidate) is not dict or type(candidate.get("version")) is not str:
        raise ValueError("candidate manifest version is unavailable")
    version = candidate["version"]
    archive = (
        args.candidate_dist
        / f"tomorrowci-v{version}-{spec.target}.{spec.archive_extension}"
    )
    with _temporary_directory(
        prefix="tomorrowci-platform-readback-",
        parent=artifact.parent,
        label="platform artifact read-back",
    ) as raw:
        extracted = package_release.extract_archive(
            archive=archive,
            output_dir=Path(raw) / "extract",
            version=version,
            target=spec.target,
        )
        expected_args = argparse.Namespace(
            metadata_root=artifact / "metadata",
            platform_id=args.platform_id,
            runner_name=runner["name"],
            runner_os=runner["os"],
            runner_arch=runner["arch"],
            project_repository=args.project_repository,
            project_source_sha=args.project_source_sha,
            project_source_ref=args.project_source_ref,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            candidate_dist=args.candidate_dist,
            candidate_binary=extracted / spec.binary_name,
            candidate_run_id=args.candidate_run_id,
            candidate_run_attempt=args.candidate_run_attempt,
            candidate_manifest_sha256=args.candidate_manifest_sha256,
            candidate_source_sha=args.candidate_source_sha,
            oci_manifest_digest=args.oci_manifest_digest,
            fixture_source=args.fixture_source,
            run_root=runs / run_id,
        )
        expected = build_record(expected_args)
    if document != expected or record_bytes != canonical_json_bytes(expected):
        raise ValueError("platform artifact record differs from current exact bytes")


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--metadata-root", type=Path, required=True)
    parser.add_argument("--platform-id", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--runner-name", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    parser.add_argument("--project-repository", required=True)
    parser.add_argument("--project-source-sha", required=True)
    parser.add_argument("--project-source-ref", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)


def _record_context(parser: argparse.ArgumentParser) -> None:
    _common(parser)
    parser.add_argument("--candidate-dist", type=Path, required=True)
    parser.add_argument("--candidate-binary", type=Path, required=True)
    parser.add_argument("--candidate-run-id", required=True)
    parser.add_argument("--candidate-run-attempt", required=True)
    parser.add_argument("--candidate-manifest-sha256", required=True)
    parser.add_argument("--candidate-source-sha", required=True)
    parser.add_argument("--oci-manifest-digest", required=True)
    parser.add_argument("--fixture-source", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Create and verify retained platform qualification evidence"
    )
    commands = root.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot-tree")
    snapshot.add_argument("--root", type=Path, required=True)
    snapshot.add_argument("--exclude-internal", action="store_true")
    snapshot.add_argument("--output", type=Path, required=True)
    capture = commands.add_parser("create-capture")
    _common(capture)
    capture.add_argument("--output", type=Path, required=True)
    create = commands.add_parser("create-record")
    _record_context(create)
    create.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify-record")
    _record_context(verify)
    verify.add_argument("--record", type=Path, required=True)
    artifact = commands.add_parser("verify-artifact")
    artifact.add_argument("--artifact-root", type=Path, required=True)
    artifact.add_argument("--candidate-dist", type=Path, required=True)
    artifact.add_argument("--candidate-run-id", required=True)
    artifact.add_argument("--candidate-run-attempt", required=True)
    artifact.add_argument("--candidate-manifest-sha256", required=True)
    artifact.add_argument("--candidate-source-sha", required=True)
    artifact.add_argument("--oci-manifest-digest", required=True)
    artifact.add_argument("--platform-id", choices=sorted(PLATFORMS), required=True)
    artifact.add_argument("--fixture-source", type=Path, required=True)
    artifact.add_argument("--project-repository", required=True)
    artifact.add_argument("--project-source-sha", required=True)
    artifact.add_argument("--project-source-ref", required=True)
    artifact.add_argument("--workflow-run-id", required=True)
    artifact.add_argument("--workflow-run-attempt", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command == "snapshot-tree":
            _write_new(
                args.output,
                tree_snapshot(args.root, exclude_internal=args.exclude_internal),
                "tree snapshot",
            )
            print(f"tree snapshot: PASS: {args.output}")
            return 0
        if args.command == "create-capture":
            capture = create_capture(
                metadata_root=args.metadata_root,
                platform_id=args.platform_id,
                runner_name=args.runner_name,
                runner_os=args.runner_os,
                runner_arch=args.runner_arch,
                project_repository=args.project_repository,
                project_source_sha=args.project_source_sha,
                project_source_ref=args.project_source_ref,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
            )
            _write_new(args.output, capture, "platform capture")
            print(f"platform capture: PASS: {args.output}")
            return 0
        if args.command == "verify-artifact":
            verify_artifact(args)
            print("platform qualification artifact: PASS")
            return 0
        expected = build_record(args)
        if args.command == "create-record":
            _write_new(args.output, expected, "platform qualification record")
            print(f"platform qualification record: PASS: {args.output}")
            return 0
        actual, data = _load_json(
            args.record, "platform qualification record", canonical=True
        )
        if actual != expected or data != canonical_json_bytes(expected):
            raise ValueError(
                "platform qualification record differs from current exact bytes"
            )
        print("platform qualification record: PASS")
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"platform qualification: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
