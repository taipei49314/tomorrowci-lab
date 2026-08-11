#!/usr/bin/env python3
"""Create and verify a detached, explicitly unauthorized OCI candidate record.

The OCI archive is inspected in place.  Nothing from the archive is extracted.
BuildKit directory exports are repacked with fixed tar metadata so the outer
archive bytes are reproducible as well as the OCI descriptors they contain.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO


KIND = "tomorrowci.oci-candidate-provenance.v1"
STATUS = "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED"
DEFAULT_PROVENANCE = Path("image-provenance.json")
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
DOCKER_TAG = re.compile(
    r"^(?=.{1,255}$)[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
FROM = re.compile(
    r"^\s*FROM\s+(?P<source>[^\s@]+)@sha256:(?P<digest>[0-9a-f]{64})"
    r"(?:\s+AS\s+[^\s]+)?\s*$",
    re.IGNORECASE,
)
MAX_JSON = 32 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_ARCHIVE_MEMBER = 8 * 1024 * 1024 * 1024
TAR_BLOCK_SIZE = 512
TAR_RECORD_SIZE = 20 * TAR_BLOCK_SIZE


def _require_directory(path: Path, label: str) -> Path:
    path = path.absolute()
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is missing or inaccessible") from exc
    if not stat.S_ISDIR(mode):
        raise ValueError(f"{label} must be a real directory")
    return path.resolve(strict=True)


def _layout_files(layout: Path) -> list[tuple[str, Path]]:
    layout = _require_directory(layout, "OCI layout")
    root_entries = {entry.name: entry for entry in layout.iterdir()}
    required_root = {"blobs", "index.json", "oci-layout"}
    if not required_root <= set(root_entries) or not (
        set(root_entries) - required_root
    ) <= {"ingest"}:
        raise ValueError("OCI layout directory has an unexpected root inventory")
    if "ingest" in root_entries:
        ingest = root_entries["ingest"]
        if not stat.S_ISDIR(ingest.lstat().st_mode) or any(ingest.iterdir()):
            raise ValueError("OCI layout ingest directory must be a real empty directory")

    blobs = root_entries["blobs"]
    sha_root = blobs / "sha256"
    if (
        not stat.S_ISDIR(blobs.lstat().st_mode)
        or {entry.name for entry in blobs.iterdir()} != {"sha256"}
        or not stat.S_ISDIR(sha_root.lstat().st_mode)
    ):
        raise ValueError("OCI layout blob directory is not canonical")

    files: list[tuple[str, Path]] = []
    for name in ("index.json", "oci-layout"):
        path = root_entries[name]
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(f"OCI layout member is not a regular file: {name}")
        files.append((name, path))
    for path in sha_root.iterdir():
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or not SHA256.fullmatch(path.name):
            raise ValueError("OCI layout contains an unsafe blob entry")
        if path.stat().st_size <= 0 or path.stat().st_size > MAX_ARCHIVE_MEMBER:
            raise ValueError(f"OCI layout blob has an unsafe size: {path.name}")
        files.append((f"blobs/sha256/{path.name}", path))
    if len(files) + 2 > MAX_MEMBERS:
        raise ValueError("OCI layout contains too many members")
    return sorted(files)


def _canonical_tar_info(name: str, *, directory: bool, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o755 if directory else 0o644
    info.size = 0 if directory else size
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.pax_headers = {}
    return info


def pack_layout(*, layout: Path, archive: Path) -> Path:
    """Create one canonical USTAR archive from a BuildKit OCI directory export."""

    files = _layout_files(layout)
    archive = archive.absolute()
    parent = _require_directory(archive.parent, "OCI archive parent")
    archive = parent / archive.name
    if archive.exists() or archive.is_symlink():
        raise ValueError("OCI archive output must not already exist")
    created = False
    try:
        with archive.open("xb") as output:
            created = True
            with tarfile.open(
                fileobj=output,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as destination:
                for directory in ("blobs", "blobs/sha256"):
                    destination.addfile(_canonical_tar_info(directory, directory=True))
                for name, source in files:
                    info = _canonical_tar_info(
                        name,
                        directory=False,
                        size=source.stat().st_size,
                    )
                    with source.open("rb") as handle:
                        destination.addfile(info, handle)
        with _OciArchive(archive):
            pass
        return archive
    except Exception:
        if created:
            archive.unlink(missing_ok=True)
        raise


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_regular(path: Path, label: str) -> Path:
    path = path.absolute()
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is missing or inaccessible") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a regular file")
    return path.resolve(strict=True)


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _load_json_bytes(data: bytes, label: str) -> object:
    if len(data) > MAX_JSON:
        raise ValueError(f"{label} exceeds the JSON size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    if text.startswith("\ufeff"):
        raise ValueError(f"{label} must not contain a UTF-8 BOM")
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not strict JSON: {exc}") from exc


def _object(value: object, label: str) -> dict:
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    return value


def _array(value: object, label: str) -> list:
    if type(value) is not list:
        raise ValueError(f"{label} must be a JSON array")
    return value


def _canonical_bytes(value: object) -> bytes:
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


def _strict_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(
            _strict_equal(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _strict_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def _validate_identity(
    *, source_sha: str, repository: str, run_id: str, run_attempt: int
) -> None:
    if type(source_sha) is not str or not SHA.fullmatch(source_sha):
        raise ValueError("source SHA must be exactly 40 lowercase hex characters")
    if type(repository) is not str or not SLUG.fullmatch(repository):
        raise ValueError("repository must be an owner/name GitHub slug")
    if type(run_id) is not str or not run_id.isascii() or not run_id.isdigit():
        raise ValueError("workflow run ID must be a positive decimal integer")
    if run_id.startswith("0") or int(run_id) < 1:
        raise ValueError("workflow run ID must be a positive decimal integer")
    if type(run_attempt) is not int or run_attempt < 1:
        raise ValueError("workflow run attempt must be a strict positive integer")


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/") or "\x00" in name:
        return False
    path = PurePosixPath(name)
    return (
        path.as_posix() == name
        and all(part not in ("", ".", "..") for part in path.parts)
    )


class _OciArchive:
    def __init__(self, path: Path):
        self.path = _require_regular(path, "OCI archive")
        self.tar: tarfile.TarFile | None = None
        self.members: dict[str, tarfile.TarInfo] = {}
        self.hashes: dict[str, str] = {}

    def __enter__(self) -> "_OciArchive":
        try:
            self.tar = tarfile.open(self.path, mode="r:*")
            members = self.tar.getmembers()
        except tarfile.TarError as exc:
            raise ValueError(f"OCI archive is not a readable tar: {exc}") from exc
        try:
            if len(members) > MAX_MEMBERS:
                raise ValueError("OCI archive contains too many members")
            for member in members:
                if not _safe_member_name(member.name):
                    raise ValueError(f"unsafe OCI archive member path: {member.name!r}")
                if member.name in self.members:
                    raise ValueError(f"duplicate OCI archive member: {member.name}")
                if member.isdir():
                    if member.name not in {"blobs", "blobs/sha256"}:
                        raise ValueError(f"unexpected OCI archive directory: {member.name}")
                elif not member.isreg():
                    raise ValueError(
                        f"OCI archive member is not a regular file: {member.name}"
                    )
                expected_mode = 0o755 if member.isdir() else 0o644
                if (
                    member.mode != expected_mode
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                    or member.linkname != ""
                    or member.pax_headers
                    or member.devmajor != 0
                    or member.devminor != 0
                ):
                    raise ValueError(
                        f"OCI archive member metadata is not canonical: {member.name}"
                    )
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER:
                    raise ValueError(
                        f"OCI archive member has an unsafe size: {member.name}"
                    )
                self.members[member.name] = member
            expected_order = [
                "blobs",
                "blobs/sha256",
                *sorted(
                    member.name
                    for member in members
                    if member.name not in {"blobs", "blobs/sha256"}
                ),
            ]
            if [member.name for member in members] != expected_order:
                raise ValueError("OCI archive member order is not canonical")
            self._verify_canonical_ustar_bytes(members)
            if {"blobs", "blobs/sha256"} - self.members.keys():
                raise ValueError("OCI archive is missing its blob directories")
            if not all(
                self.members[name].isdir() for name in ("blobs", "blobs/sha256")
            ):
                raise ValueError("OCI blob directory entries must be directories")
        except Exception:
            self.tar.close()
            self.tar = None
            raise
        return self

    def _verify_canonical_ustar_bytes(self, members: list[tarfile.TarInfo]) -> None:
        if not members:
            raise ValueError("OCI archive contains no members")
        with self.path.open("rb") as raw:
            for member in members:
                if member.offset % TAR_BLOCK_SIZE != 0:
                    raise ValueError("OCI archive has a non-aligned tar header")
                raw.seek(member.offset)
                header = raw.read(TAR_BLOCK_SIZE)
                if (
                    len(header) != TAR_BLOCK_SIZE
                    or header[257:263] != b"ustar\0"
                    or header[263:265] != b"00"
                ):
                    raise ValueError("OCI archive must use canonical uncompressed USTAR")
                expected_header = _canonical_tar_info(
                    member.name,
                    directory=member.isdir(),
                    size=member.size,
                ).tobuf(
                    format=tarfile.USTAR_FORMAT,
                    encoding="utf-8",
                    errors="strict",
                )
                if header != expected_header:
                    raise ValueError(
                        f"OCI archive has a non-canonical USTAR header: {member.name}"
                    )

            last = members[-1]
            data_end = last.offset_data + (
                (last.size + TAR_BLOCK_SIZE - 1) // TAR_BLOCK_SIZE
            ) * TAR_BLOCK_SIZE
            minimum_end = data_end + 2 * TAR_BLOCK_SIZE
            expected_size = (
                (minimum_end + TAR_RECORD_SIZE - 1) // TAR_RECORD_SIZE
            ) * TAR_RECORD_SIZE
            raw.seek(0, 2)
            if raw.tell() != expected_size:
                raise ValueError("OCI archive has non-canonical EOF length")
            raw.seek(data_end)
            for chunk in iter(lambda: raw.read(1024 * 1024), b""):
                if any(chunk):
                    raise ValueError("OCI archive EOF blocks and padding must be zero")

    def __exit__(self, *_: object) -> None:
        if self.tar is not None:
            self.tar.close()

    def _stream(self, name: str) -> BinaryIO:
        member = self.members.get(name)
        if member is None or not member.isreg() or self.tar is None:
            raise ValueError(f"OCI archive is missing regular member: {name}")
        stream = self.tar.extractfile(member)
        if stream is None:
            raise ValueError(f"OCI archive member cannot be read: {name}")
        return stream

    def read(self, name: str, *, limit: int = MAX_JSON) -> bytes:
        member = self.members.get(name)
        if member is None or not member.isreg():
            raise ValueError(f"OCI archive is missing regular member: {name}")
        if member.size > limit:
            raise ValueError(f"OCI archive member exceeds size limit: {name}")
        with self._stream(name) as stream:
            data = stream.read(limit + 1)
        if len(data) != member.size:
            raise ValueError(f"OCI archive member size is inconsistent: {name}")
        return data

    def hash(self, name: str) -> str:
        if name in self.hashes:
            return self.hashes[name]
        digest = hashlib.sha256()
        total = 0
        with self._stream(name) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(chunk)
                digest.update(chunk)
        if total != self.members[name].size:
            raise ValueError(f"OCI archive member size is inconsistent: {name}")
        value = digest.hexdigest()
        self.hashes[name] = value
        return value

    def blob(self, digest: str, *, json_blob: bool = False) -> bytes:
        if type(digest) is not str or not digest.startswith("sha256:"):
            raise ValueError("OCI descriptor must use a sha256 digest")
        value = digest[7:]
        if not SHA256.fullmatch(value):
            raise ValueError("OCI descriptor has a malformed sha256 digest")
        name = f"blobs/sha256/{value}"
        if self.hash(name) != value:
            raise ValueError(f"OCI blob filename/content digest mismatch: {name}")
        return self.read(name) if json_blob else b""


def _descriptor(
    value: object,
    label: str,
    *,
    media_type: str | None = None,
    require_platform: bool = False,
) -> dict:
    descriptor = _object(value, label)
    allowed = {"mediaType", "digest", "size", "annotations", "platform"}
    required = {"mediaType", "digest", "size"}
    if not required <= descriptor.keys() or not descriptor.keys() <= allowed:
        raise ValueError(f"{label} has an unexpected descriptor schema")
    if type(descriptor["mediaType"]) is not str or (
        media_type is not None and descriptor["mediaType"] != media_type
    ):
        raise ValueError(f"{label} media type mismatch")
    digest = descriptor["digest"]
    if (
        type(digest) is not str
        or not digest.startswith("sha256:")
        or not SHA256.fullmatch(digest[7:])
    ):
        raise ValueError(f"{label} digest is malformed")
    if type(descriptor["size"]) is not int or descriptor["size"] <= 0:
        raise ValueError(f"{label} size must be a strict positive integer")
    if "annotations" in descriptor:
        annotations = _object(descriptor["annotations"], f"{label} annotations")
        if any(type(key) is not str or type(item) is not str for key, item in annotations.items()):
            raise ValueError(f"{label} annotations must contain only strings")
    if require_platform:
        if descriptor.get("platform") != {"architecture": "amd64", "os": "linux"}:
            raise ValueError(f"{label} must be exactly linux/amd64")
    elif "platform" in descriptor:
        _object(descriptor["platform"], f"{label} platform")
    return descriptor


def _read_descriptor_json(
    archive: _OciArchive, descriptor: dict, label: str
) -> tuple[dict, bytes]:
    data = archive.blob(descriptor["digest"], json_blob=True)
    if len(data) != descriptor["size"]:
        raise ValueError(f"{label} descriptor size mismatch")
    return _object(_load_json_bytes(data, label), label), data


def _validate_oci_graph(archive: _OciArchive) -> dict:
    """Validate the complete canonical single-platform OCI payload graph."""

    referenced: set[str] = set()
    layout_raw = archive.read("oci-layout")
    layout = _object(_load_json_bytes(layout_raw, "oci-layout"), "oci-layout")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("OCI layout version/schema mismatch")
    index_raw = archive.read("index.json")
    layout_index = _object(
        _load_json_bytes(index_raw, "OCI layout index"), "OCI layout index"
    )
    if set(layout_index) != {"schemaVersion", "mediaType", "manifests"}:
        raise ValueError("OCI layout index has an unexpected schema")
    if (
        type(layout_index["schemaVersion"]) is not int
        or layout_index["schemaVersion"] != 2
        or layout_index["mediaType"] != OCI_INDEX
    ):
        raise ValueError("OCI layout index identity mismatch")
    roots = _array(layout_index["manifests"], "OCI layout descriptors")
    if len(roots) != 1:
        raise ValueError("detached provenance mode requires exactly one image manifest")
    manifest_descriptor = _descriptor(
        roots[0],
        "OCI image manifest descriptor",
        media_type=OCI_MANIFEST,
        require_platform=True,
    )
    referenced.add(manifest_descriptor["digest"][7:])
    manifest, _ = _read_descriptor_json(
        archive, manifest_descriptor, "OCI image manifest"
    )
    allowed_manifest = {"schemaVersion", "mediaType", "config", "layers"}
    if (
        not {"schemaVersion", "mediaType", "config", "layers"} <= manifest.keys()
        or not manifest.keys() <= allowed_manifest
        or type(manifest["schemaVersion"]) is not int
        or manifest["schemaVersion"] != 2
        or manifest["mediaType"] != OCI_MANIFEST
    ):
        raise ValueError("OCI image manifest schema mismatch")
    config_descriptor = _descriptor(
        manifest["config"], "OCI config descriptor", media_type=OCI_CONFIG
    )
    referenced.add(config_descriptor["digest"][7:])
    config, _ = _read_descriptor_json(archive, config_descriptor, "OCI config")
    raw_layers = _array(manifest["layers"], "OCI layers")
    if not raw_layers:
        raise ValueError("OCI image manifest contains no layers")
    layers: list[dict] = []
    for position, value in enumerate(raw_layers):
        layer = _descriptor(value, f"OCI layer {position}")
        if not layer["mediaType"].startswith("application/vnd.oci.image.layer.v1."):
            raise ValueError(f"OCI layer {position} has an unsupported media type")
        referenced.add(layer["digest"][7:])
        archive.blob(layer["digest"])
        layer_member = archive.members[f"blobs/sha256/{layer['digest'][7:]}"]
        if layer_member.size != layer["size"]:
            raise ValueError(f"OCI layer {position} descriptor size mismatch")
        layers.append(layer)

    if config.get("architecture") != "amd64" or config.get("os") != "linux":
        raise ValueError("OCI config platform must be exactly linux/amd64")
    rootfs = _object(config.get("rootfs"), "OCI rootfs config")
    diff_ids = _array(rootfs.get("diff_ids"), "OCI rootfs diff IDs")
    if (
        rootfs.get("type") != "layers"
        or len(diff_ids) != len(layers)
        or any(
            type(value) is not str
            or not value.startswith("sha256:")
            or not SHA256.fullmatch(value[7:])
            for value in diff_ids
        )
    ):
        raise ValueError("OCI rootfs diff IDs do not match the layer inventory")

    actual_blobs = {
        name.removeprefix("blobs/sha256/")
        for name, member in archive.members.items()
        if member.isreg() and name.startswith("blobs/sha256/")
    }
    if any(not SHA256.fullmatch(value) for value in actual_blobs):
        raise ValueError("OCI blob filenames must be lowercase sha256 values")
    for value in actual_blobs:
        if archive.hash(f"blobs/sha256/{value}") != value:
            raise ValueError("OCI blob filename/content sha256 mismatch")
    if actual_blobs != referenced:
        raise ValueError("OCI archive contains missing or unreferenced blobs")
    expected_files = {
        "blobs",
        "blobs/sha256",
        "index.json",
        "oci-layout",
        *(f"blobs/sha256/{value}" for value in actual_blobs),
    }
    if set(archive.members) != expected_files:
        raise ValueError("OCI archive contains unexpected extra members")
    return {
        "config": config,
        "config_descriptor": config_descriptor,
        "index_raw": index_raw,
        "layers": layers,
        "manifest_descriptor": manifest_descriptor,
    }


def _parse_containerfile(path: Path) -> tuple[str, int, list[dict[str, str]]]:
    path = _require_regular(path, "Containerfile")
    if path.name != "Containerfile":
        raise ValueError("container build definition must be named Containerfile")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Containerfile is not UTF-8") from exc
    materials = []
    for line in text.splitlines():
        if not line.lstrip().upper().startswith("FROM "):
            continue
        match = FROM.fullmatch(line)
        if match is None:
            raise ValueError("every Containerfile FROM must be digest pinned")
        if match.group("digest") != match.group("digest").lower():
            raise ValueError("Containerfile sha256 pins must use lowercase hex")
        materials.append(
            {
                "source": match.group("source"),
                "sha256": f"sha256:{match.group('digest')}",
            }
        )
    if not materials:
        raise ValueError("Containerfile contains no pinned base image materials")
    digests = [entry["sha256"] for entry in materials]
    if len(set(digests)) != len(digests):
        raise ValueError("Containerfile base image material digests must be unique")
    return _digest_bytes(raw), len(raw), materials


def _validate_metadata(
    *,
    path: Path,
    image_descriptor: dict,
    materials: list[dict[str, str]],
    version: str,
    source_sha: str,
    repository: str,
) -> tuple[str, str, int]:
    path = _require_regular(path, "buildx metadata")
    raw = path.read_bytes()
    metadata = _object(_load_json_bytes(raw, "buildx metadata"), "buildx metadata")
    digest = image_descriptor["digest"]
    if metadata.get("containerimage.digest") != digest:
        raise ValueError("buildx metadata digest does not match the OCI image manifest")
    descriptor = _object(
        metadata.get("containerimage.descriptor"), "buildx image descriptor"
    )
    if (
        descriptor.get("digest") != digest
        or descriptor.get("mediaType") != image_descriptor["mediaType"]
        or type(descriptor.get("size")) is not int
        or descriptor["size"] != image_descriptor["size"]
    ):
        raise ValueError("buildx image descriptor does not match the OCI image manifest")
    provenance = _object(
        metadata.get("buildx.build.provenance"), "buildx metadata provenance"
    )
    if provenance.get("buildType") != "https://mobyproject.org/buildkit@v1":
        raise ValueError("buildx metadata provenance build type mismatch")
    raw_materials = _array(provenance.get("materials"), "buildx materials")
    actual_materials: dict[str, str] = {}
    for position, value in enumerate(raw_materials):
        item = _object(value, f"buildx material {position}")
        if set(item) != {"uri", "digest"} or type(item["uri"]) is not str:
            raise ValueError("buildx material schema mismatch")
        item_digest = _object(item["digest"], "buildx material digest")
        if set(item_digest) != {"sha256"}:
            raise ValueError("buildx material must contain exactly one sha256 digest")
        sha = item_digest["sha256"]
        if type(sha) is not str or not SHA256.fullmatch(sha) or sha in actual_materials:
            raise ValueError("buildx material sha256 digest is malformed or duplicated")
        actual_materials[sha] = item["uri"]
    expected_digests = {entry["sha256"][7:] for entry in materials}
    if set(actual_materials) != expected_digests:
        raise ValueError("buildx materials do not match Containerfile base image digests")
    for entry in materials:
        sha = entry["sha256"][7:]
        package = entry["source"].removeprefix("docker.io/library/")
        expected_uri = (
            f"pkg:docker/{package}?digest=sha256:{sha}&platform=linux%2Famd64"
        )
        if actual_materials[sha] != expected_uri:
            raise ValueError("buildx material URI does not match its Containerfile source")

    invocation = _object(provenance.get("invocation"), "buildx invocation")
    config_source = _object(invocation.get("configSource"), "buildx config source")
    if config_source.get("entryPoint") != "Containerfile":
        raise ValueError("buildx provenance did not use Containerfile")
    environment = _object(invocation.get("environment"), "buildx environment")
    if environment.get("platform") != "linux/amd64":
        raise ValueError("buildx platform must be exactly linux/amd64")
    parameters = _object(invocation.get("parameters"), "buildx parameters")
    args = _object(parameters.get("args"), "buildx build arguments")
    if (
        args.get("build-arg:TCI_REVISION") != source_sha
        or args.get("build-arg:TCI_VERSION") != version
    ):
        raise ValueError("buildx build arguments do not match candidate identity")
    root = _object(parameters.get("root"), "buildx root parameters")
    root_source = _object(root.get("configSource"), "buildx root config source")
    if root_source.get("path") != "Containerfile":
        raise ValueError("buildx root config source is not Containerfile")
    request = _object(root.get("request"), "buildx root request")
    request_args = _object(request.get("args"), "buildx root request arguments")
    source_urls = {
        f"https://github.com/{repository}",
        f"https://github.com/{repository}.git",
    }
    if (
        request_args.get("vcs:revision") != source_sha
        or request_args.get("vcs:source") not in source_urls
        or request_args.get("build-arg:TCI_REVISION") != source_sha
        or request_args.get("build-arg:TCI_VERSION") != version
    ):
        raise ValueError("buildx VCS identity does not match the exact candidate source")
    return _digest_bytes(raw), path.name, len(raw)


def _inspect_oci(
    *,
    archive_path: Path,
    metadata_path: Path,
    containerfile_path: Path,
    version: str,
    source_sha: str,
    repository: str,
) -> dict:
    if type(version) is not str or not SEMVER.fullmatch(version):
        raise ValueError("OCI candidate version must be SemVer")
    containerfile_sha, containerfile_size, materials = _parse_containerfile(
        containerfile_path
    )
    archive_path = _require_regular(archive_path, "OCI archive")
    archive_size = archive_path.stat().st_size
    archive_sha = sha256_file(archive_path)
    with _OciArchive(archive_path) as archive:
        graph = _validate_oci_graph(archive)
        runtime = _object(graph["config"].get("config"), "OCI runtime config")
        labels = _object(runtime.get("Labels"), "OCI image labels")
        expected_source = f"https://github.com/{repository}"
        expected_labels = {
            "org.opencontainers.image.version": version,
            "org.opencontainers.image.revision": source_sha,
            "org.opencontainers.image.source": expected_source,
        }
        if any(
            type(labels.get(name)) is not str or labels.get(name) != value
            for name, value in expected_labels.items()
        ):
            raise ValueError("OCI version/revision/source labels do not match candidate identity")
        if type(runtime.get("User")) is not str or runtime["User"] != "65532:65532":
            raise ValueError("OCI runtime user must be exactly 65532:65532")
        entrypoint = runtime.get("Entrypoint")
        if (
            type(entrypoint) is not list
            or entrypoint != ["/usr/local/bin/tomorrowci"]
            or any(type(item) is not str for item in entrypoint)
        ):
            raise ValueError("OCI entrypoint must be the TomorrowCI binary")

    if (
        archive_path.stat().st_size != archive_size
        or sha256_file(archive_path) != archive_sha
    ):
        raise ValueError("OCI archive changed while it was being inspected")

    metadata_sha, metadata_name, metadata_size = _validate_metadata(
        path=metadata_path,
        image_descriptor=graph["manifest_descriptor"],
        materials=materials,
        version=version,
        source_sha=source_sha,
        repository=repository,
    )
    return {
        "archive": {
            "name": archive_path.name,
            "sha256": f"sha256:{archive_sha}",
            "size": archive_size,
        },
        "layout_index": {"sha256": f"sha256:{_digest_bytes(graph['index_raw'])}"},
        "manifest": {
            "digest": graph["manifest_descriptor"]["digest"],
            "media_type": graph["manifest_descriptor"]["mediaType"],
            "size": graph["manifest_descriptor"]["size"],
        },
        "config": {
            "digest": graph["config_descriptor"]["digest"],
            "media_type": graph["config_descriptor"]["mediaType"],
            "size": graph["config_descriptor"]["size"],
        },
        "platform": {"architecture": "amd64", "os": "linux"},
        "runtime": {
            "entrypoint": ["/usr/local/bin/tomorrowci"],
            "user": "65532:65532",
        },
        "build": {
            "containerfile": {
                "name": "Containerfile",
                "sha256": f"sha256:{containerfile_sha}",
                "size": containerfile_size,
            },
            "metadata": {
                "name": metadata_name,
                "sha256": f"sha256:{metadata_sha}",
                "size": metadata_size,
            },
            "materials": materials,
        },
    }


def _validate_docker_tag(tag: str) -> None:
    if type(tag) is not str or not DOCKER_TAG.fullmatch(tag):
        raise ValueError("Docker smoke tag must be one canonical name:tag reference")


def _docker_manifest(*, graph: dict, tag: str) -> tuple[bytes, str, list[str]]:
    _validate_docker_tag(tag)
    config_path = f"blobs/sha256/{graph['config_descriptor']['digest'][7:]}"
    layer_paths = [
        f"blobs/sha256/{layer['digest'][7:]}" for layer in graph["layers"]
    ]
    document = [
        {
            "Config": config_path,
            "Layers": layer_paths,
            "RepoTags": [tag],
        }
    ]
    return _canonical_bytes(document), config_path, layer_paths


def verify_docker_archive(
    *,
    archive: Path,
    docker_archive: Path,
    tag: str,
    expected_oci_sha256: str,
) -> dict:
    """Verify an exact-payload Docker-load carrier derived from canonical OCI."""

    _validate_docker_tag(tag)
    if (
        type(expected_oci_sha256) is not str
        or not expected_oci_sha256.startswith("sha256:")
        or not SHA256.fullmatch(expected_oci_sha256[7:])
    ):
        raise ValueError("expected OCI archive digest must be one sha256 digest")
    archive = _require_regular(archive, "OCI archive")
    source_size = archive.stat().st_size
    source_sha = sha256_file(archive)
    if f"sha256:{source_sha}" != expected_oci_sha256:
        raise ValueError("OCI archive digest does not match the verified candidate")
    with _OciArchive(archive) as source:
        graph = _validate_oci_graph(source)
        expected_manifest, config_path, layer_paths = _docker_manifest(
            graph=graph, tag=tag
        )
        payload_paths = sorted({config_path, *layer_paths})
        payload_sizes = {
            name: source.members[name].size for name in payload_paths
        }
        payload_hashes = {name: source.hash(name) for name in payload_paths}
    if archive.stat().st_size != source_size or sha256_file(archive) != source_sha:
        raise ValueError("OCI archive changed while deriving the Docker smoke archive")

    docker_archive = _require_regular(docker_archive, "Docker smoke archive")
    docker_size = docker_archive.stat().st_size
    docker_sha = sha256_file(docker_archive)
    with _OciArchive(docker_archive) as derived:
        expected_members = {
            "blobs",
            "blobs/sha256",
            "manifest.json",
            *payload_paths,
        }
        if set(derived.members) != expected_members:
            raise ValueError("Docker smoke archive contains unexpected extra members")
        manifest_raw = derived.read("manifest.json")
        manifest = _array(
            _load_json_bytes(manifest_raw, "Docker manifest"), "Docker manifest"
        )
        if manifest_raw != _canonical_bytes(manifest):
            raise ValueError("Docker manifest is not canonical JSON")
        if len(manifest) != 1:
            raise ValueError("Docker manifest must contain exactly one image")
        entry = _object(manifest[0], "Docker manifest image")
        if set(entry) != {"Config", "Layers", "RepoTags"}:
            raise ValueError("Docker manifest image has an unexpected schema")
        if manifest_raw != expected_manifest:
            raise ValueError(
                "Docker manifest config, layers, or tag do not match the OCI payload"
            )
        for name in payload_paths:
            if (
                derived.members[name].size != payload_sizes[name]
                or derived.hash(name) != payload_hashes[name]
            ):
                raise ValueError(
                    f"Docker smoke payload is not byte-identical to OCI: {name}"
                )
    if (
        docker_archive.stat().st_size != docker_size
        or sha256_file(docker_archive) != docker_sha
    ):
        raise ValueError("Docker smoke archive changed while it was being verified")
    return {
        "config": config_path,
        "docker_archive": {
            "sha256": f"sha256:{docker_sha}",
            "size": docker_size,
        },
        "layers": layer_paths,
        "oci_archive": {
            "sha256": f"sha256:{source_sha}",
            "size": source_size,
        },
        "tag": tag,
    }


def create_docker_archive(
    *,
    archive: Path,
    docker_archive: Path,
    tag: str,
    expected_oci_sha256: str,
) -> dict:
    """Create a deterministic, non-shipping Docker-load smoke carrier."""

    _validate_docker_tag(tag)
    if (
        type(expected_oci_sha256) is not str
        or not expected_oci_sha256.startswith("sha256:")
        or not SHA256.fullmatch(expected_oci_sha256[7:])
    ):
        raise ValueError("expected OCI archive digest must be one sha256 digest")
    archive = _require_regular(archive, "OCI archive")
    source_size = archive.stat().st_size
    source_sha = sha256_file(archive)
    if f"sha256:{source_sha}" != expected_oci_sha256:
        raise ValueError("OCI archive digest does not match the verified candidate")
    docker_archive = docker_archive.absolute()
    parent = _require_directory(docker_archive.parent, "Docker archive parent")
    docker_archive = parent / docker_archive.name
    if docker_archive.exists() or docker_archive.is_symlink():
        raise ValueError("Docker smoke archive output must not already exist")

    created = False
    try:
        with _OciArchive(archive) as source:
            graph = _validate_oci_graph(source)
            manifest_raw, config_path, layer_paths = _docker_manifest(
                graph=graph, tag=tag
            )
            payload_paths = sorted({config_path, *layer_paths})
            with docker_archive.open("xb") as output:
                created = True
                with tarfile.open(
                    fileobj=output,
                    mode="w",
                    format=tarfile.USTAR_FORMAT,
                ) as destination:
                    for directory in ("blobs", "blobs/sha256"):
                        destination.addfile(
                            _canonical_tar_info(directory, directory=True)
                        )
                    for name in payload_paths:
                        info = _canonical_tar_info(
                            name,
                            directory=False,
                            size=source.members[name].size,
                        )
                        with source._stream(name) as handle:
                            destination.addfile(info, handle)
                    destination.addfile(
                        _canonical_tar_info(
                            "manifest.json", directory=False, size=len(manifest_raw)
                        ),
                        io.BytesIO(manifest_raw),
                    )
        if archive.stat().st_size != source_size or sha256_file(archive) != source_sha:
            raise ValueError("OCI archive changed while deriving the Docker smoke archive")
        return verify_docker_archive(
            archive=archive,
            docker_archive=docker_archive,
            tag=tag,
            expected_oci_sha256=expected_oci_sha256,
        )
    except Exception:
        if created:
            docker_archive.unlink(missing_ok=True)
        raise


def _candidate_document(
    *,
    inspection: dict,
    version: str,
    source_sha: str,
    repository: str,
    run_id: str,
    run_attempt: int,
    server_url: str,
) -> dict:
    _validate_identity(
        source_sha=source_sha,
        repository=repository,
        run_id=run_id,
        run_attempt=run_attempt,
    )
    if type(server_url) is not str or server_url != "https://github.com":
        raise ValueError("candidate server URL must be exactly https://github.com")
    run_url = f"{server_url}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
    return {
        "schema_version": 1,
        "kind": KIND,
        "status": STATUS,
        "version": version,
        "source": {
            "commit": source_sha,
            "repository": repository,
            "url": f"https://github.com/{repository}",
        },
        "workflow": {
            "run_attempt": run_attempt,
            "run_id": int(run_id),
            "run_url": run_url,
        },
        "oci": {key: value for key, value in inspection.items() if key != "build"},
        "build": inspection["build"],
        "promotion": {
            "authorization_source": None,
            "authorized": False,
            "instruction": (
                "Bind independent exact-SHA authorization to this provenance digest "
                "before any release or registry publication."
            ),
        },
    }


def create_candidate(
    *,
    archive: Path,
    metadata: Path,
    containerfile: Path,
    provenance: Path = DEFAULT_PROVENANCE,
    version: str,
    source_sha: str,
    repository: str,
    run_id: str,
    run_attempt: int,
    server_url: str = "https://github.com",
) -> dict:
    _validate_identity(
        source_sha=source_sha,
        repository=repository,
        run_id=run_id,
        run_attempt=run_attempt,
    )
    inspection = _inspect_oci(
        archive_path=archive,
        metadata_path=metadata,
        containerfile_path=containerfile,
        version=version,
        source_sha=source_sha,
        repository=repository,
    )
    document = _candidate_document(
        inspection=inspection,
        version=version,
        source_sha=source_sha,
        repository=repository,
        run_id=run_id,
        run_attempt=run_attempt,
        server_url=server_url,
    )
    provenance = provenance.absolute()
    if provenance.exists() or provenance.is_symlink():
        raise ValueError("detached provenance output already exists")
    if not provenance.parent.is_dir():
        raise ValueError("detached provenance parent directory does not exist")
    with provenance.open("xb") as handle:
        handle.write(_canonical_bytes(document))
    verify_candidate(
        archive=archive,
        metadata=metadata,
        containerfile=containerfile,
        provenance=provenance,
        expected_source_sha=source_sha,
        expected_repository=repository,
        expected_run_id=run_id,
        expected_run_attempt=run_attempt,
    )
    return document


def verify_candidate(
    *,
    archive: Path,
    metadata: Path,
    containerfile: Path,
    provenance: Path = DEFAULT_PROVENANCE,
    expected_source_sha: str | None = None,
    expected_repository: str | None = None,
    expected_run_id: str | None = None,
    expected_run_attempt: int | None = None,
) -> dict:
    provenance = _require_regular(provenance, "detached provenance")
    raw = provenance.read_bytes()
    document = _object(
        _load_json_bytes(raw, "detached provenance"), "detached provenance"
    )
    if raw != _canonical_bytes(document):
        raise ValueError("detached provenance is not canonical JSON")
    if set(document) != {
        "schema_version",
        "kind",
        "status",
        "version",
        "source",
        "workflow",
        "oci",
        "build",
        "promotion",
    }:
        raise ValueError("detached provenance has an unexpected top-level schema")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or type(document["kind"]) is not str
        or document["kind"] != KIND
        or type(document["status"]) is not str
        or document["status"] != STATUS
        or type(document["version"]) is not str
    ):
        raise ValueError("detached provenance identity mismatch")
    source = _object(document["source"], "detached source")
    workflow = _object(document["workflow"], "detached workflow")
    if set(source) != {"commit", "repository", "url"} or set(workflow) != {
        "run_attempt",
        "run_id",
        "run_url",
    }:
        raise ValueError("detached source/workflow schema mismatch")
    if type(workflow["run_id"]) is not int or type(workflow["run_attempt"]) is not int:
        raise ValueError("detached workflow identity must use strict integers")
    run_id = str(workflow["run_id"])
    _validate_identity(
        source_sha=source["commit"],
        repository=source["repository"],
        run_id=run_id,
        run_attempt=workflow["run_attempt"],
    )
    if expected_source_sha is not None and source["commit"] != expected_source_sha:
        raise ValueError("detached provenance source SHA does not match expected SHA")
    if expected_repository is not None and source["repository"] != expected_repository:
        raise ValueError("detached provenance repository does not match expected repository")
    if expected_run_id is not None and run_id != expected_run_id:
        raise ValueError("detached provenance run ID does not match expected run")
    if (
        expected_run_attempt is not None
        and workflow["run_attempt"] != expected_run_attempt
    ):
        raise ValueError("detached provenance run attempt does not match expected attempt")
    inspection = _inspect_oci(
        archive_path=archive,
        metadata_path=metadata,
        containerfile_path=containerfile,
        version=document["version"],
        source_sha=source["commit"],
        repository=source["repository"],
    )
    expected = _candidate_document(
        inspection=inspection,
        version=document["version"],
        source_sha=source["commit"],
        repository=source["repository"],
        run_id=run_id,
        run_attempt=workflow["run_attempt"],
        server_url="https://github.com",
    )
    if not _strict_equal(document, expected):
        raise ValueError("detached provenance does not match the exact OCI candidate inputs")
    return document


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--containerfile", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, default=DEFAULT_PROVENANCE)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack-layout")
    pack.add_argument("--layout", type=Path, required=True)
    pack.add_argument("--archive", type=Path, required=True)
    create = commands.add_parser("create")
    _add_common(create)
    create.add_argument("--version", required=True)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--run-attempt", type=int, required=True)
    create.add_argument("--server-url", default="https://github.com")
    verify = commands.add_parser("verify")
    _add_common(verify)
    verify.add_argument("--expected-source-sha")
    verify.add_argument("--expected-repository")
    verify.add_argument("--expected-run-id")
    verify.add_argument("--expected-run-attempt", type=int)
    docker = commands.add_parser("docker-archive")
    _add_common(docker)
    docker.add_argument("--docker-archive", type=Path, required=True)
    docker.add_argument("--tag", required=True)
    docker.add_argument("--expected-source-sha", required=True)
    docker.add_argument("--expected-repository", required=True)
    docker.add_argument("--expected-run-id", required=True)
    docker.add_argument("--expected-run-attempt", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "pack-layout":
            packed = pack_layout(layout=args.layout, archive=args.archive)
            print(f"oci-layout: PASS: sha256:{sha256_file(packed)}")
            return 0
        if args.command == "create":
            create_candidate(
                archive=args.archive,
                metadata=args.metadata,
                containerfile=args.containerfile,
                provenance=args.provenance,
                version=args.version,
                source_sha=args.source_sha,
                repository=args.repository,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                server_url=args.server_url,
            )
        elif args.command == "verify":
            verify_candidate(
                archive=args.archive,
                metadata=args.metadata,
                containerfile=args.containerfile,
                provenance=args.provenance,
                expected_source_sha=args.expected_source_sha,
                expected_repository=args.expected_repository,
                expected_run_id=args.expected_run_id,
                expected_run_attempt=args.expected_run_attempt,
            )
        else:
            document = verify_candidate(
                archive=args.archive,
                metadata=args.metadata,
                containerfile=args.containerfile,
                provenance=args.provenance,
                expected_source_sha=args.expected_source_sha,
                expected_repository=args.expected_repository,
                expected_run_id=args.expected_run_id,
                expected_run_attempt=args.expected_run_attempt,
            )
            result = create_docker_archive(
                archive=args.archive,
                docker_archive=args.docker_archive,
                tag=args.tag,
                expected_oci_sha256=document["oci"]["archive"]["sha256"],
            )
            print(
                "docker-smoke-archive: PASS: "
                f"{result['docker_archive']['sha256']}"
            )
            return 0
        print(f"oci-candidate: PASS: sha256:{sha256_file(args.provenance.absolute())}")
    except (OSError, TypeError, ValueError, tarfile.TarError) as exc:
        print(f"oci-candidate: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
