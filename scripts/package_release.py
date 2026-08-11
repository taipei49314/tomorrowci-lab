#!/usr/bin/env python3
"""Create and verify deterministic TomorrowCI release archives."""

from __future__ import annotations

import argparse
import gzip
import io
import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DOCS = ("README.md", "LICENSE", "CHANGELOG.md")
WINDOWS_TARGET = "x86_64-pc-windows-msvc"
ALLOWED_TARGETS = {
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    WINDOWS_TARGET,
}
FIXED_MTIME = 0
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
GZIP_HEADER = bytes.fromhex("1f8b08000000000002ff")


def stage_name(version: str, target: str) -> str:
    if target not in ALLOWED_TARGETS:
        raise ValueError(f"unsupported release target: {target}")
    if not version or "/" in version or "\\" in version:
        raise ValueError(f"invalid release version: {version!r}")
    return f"tomorrowci-v{version}-{target}"


def expected_entries(version: str, target: str) -> list[tuple[str, int]]:
    root = stage_name(version, target)
    executable = "tomorrowci.exe" if target == WINDOWS_TARGET else "tomorrowci"
    return [
        (f"{root}/", 0o755),
        (f"{root}/{executable}", 0o755),
        *( (f"{root}/{name}", 0o644) for name in DOCS ),
    ]


def _read_inputs(source_root: Path, binary: Path, target: str) -> dict[str, bytes]:
    paths = {name: source_root / name for name in DOCS}
    executable = "tomorrowci.exe" if target == WINDOWS_TARGET else "tomorrowci"
    paths[executable] = binary
    payload: dict[str, bytes] = {}
    for name, path in paths.items():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"release input must be a regular file: {path}")
        payload[name] = path.read_bytes()
    return payload


def _tar_bytes(version: str, target: str, payload: dict[str, bytes]) -> bytes:
    root = stage_name(version, target)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        directory = tarfile.TarInfo(f"{root}/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.uid = directory.gid = 0
        directory.uname = directory.gname = ""
        directory.mtime = FIXED_MTIME
        archive.addfile(directory)
        executable = "tomorrowci"
        for name in (executable, *DOCS):
            data = payload[name]
            entry = tarfile.TarInfo(f"{root}/{name}")
            entry.size = len(data)
            entry.mode = 0o755 if name == executable else 0o644
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = ""
            entry.mtime = FIXED_MTIME
            archive.addfile(entry, io.BytesIO(data))
    result = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=result, mode="wb", mtime=FIXED_MTIME) as zipped:
        zipped.write(raw.getvalue())
    return result.getvalue()


def _zip_bytes(version: str, target: str, payload: dict[str, bytes]) -> bytes:
    root = stage_name(version, target)
    result = io.BytesIO()
    with zipfile.ZipFile(
        result, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        names = [(f"{root}/", b"", 0o755)]
        names.extend(
            (f"{root}/{name}", payload[name], 0o755 if name == "tomorrowci.exe" else 0o644)
            for name in ("tomorrowci.exe", *DOCS)
        )
        for name, data, mode in names:
            entry = zipfile.ZipInfo(name, ZIP_EPOCH)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            file_type = stat.S_IFDIR if name.endswith("/") else stat.S_IFREG
            entry.external_attr = ((file_type | mode) & 0xFFFF) << 16
            if name.endswith("/"):
                entry.external_attr |= 0x10
            entry.flag_bits |= 0x800
            archive.writestr(entry, data)
        archive.comment = b""
    return result.getvalue()


def create_archive(
    *, source_root: Path, binary: Path, output_dir: Path, version: str, target: str
) -> Path:
    source_root = source_root.resolve()
    binary = binary.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = _read_inputs(source_root, binary, target)
    name = stage_name(version, target)
    if target == WINDOWS_TARGET:
        archive = output_dir / f"{name}.zip"
        data = _zip_bytes(version, target, payload)
    else:
        archive = output_dir / f"{name}.tar.gz"
        data = _tar_bytes(version, target, payload)
    if archive.exists():
        raise ValueError(f"refusing to overwrite release archive: {archive}")
    archive.write_bytes(data)
    verify_archive(
        archive=archive, version=version, target=target, expected_payload=payload
    )
    return archive


def _safe_member(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError(f"unsafe archive member: {name!r}")


def verify_archive(
    *,
    archive: Path,
    version: str,
    target: str,
    expected_payload: dict[str, bytes] | None = None,
) -> None:
    expected = expected_entries(version, target)
    expected_modes = dict(expected)
    observed_payload: dict[str, bytes] = {}
    if target == WINDOWS_TARGET:
        with zipfile.ZipFile(archive) as bundle:
            if bundle.comment:
                raise ValueError("ZIP archive comment is forbidden")
            actual = []
            for info in bundle.infolist():
                _safe_member(info.filename)
                raw_mode = (info.external_attr >> 16) & 0xFFFF
                mode = raw_mode & 0o777
                actual.append((info.filename, mode))
                expected_mode = expected_modes.get(info.filename)
                file_type = stat.S_IFDIR if info.filename.endswith("/") else stat.S_IFREG
                expected_attr = ((file_type | (expected_mode or 0)) & 0xFFFF) << 16
                if info.filename.endswith("/"):
                    expected_attr |= 0x10
                if expected_mode is None or info.external_attr != expected_attr:
                    raise ValueError(f"non-canonical ZIP type/permissions: {info.filename}")
                if info.date_time != ZIP_EPOCH:
                    raise ValueError(f"non-deterministic ZIP timestamp: {info.filename}")
                if info.create_system != 3 or info.extra or info.comment:
                    raise ValueError(f"non-canonical ZIP metadata: {info.filename}")
                if info.compress_type != zipfile.ZIP_DEFLATED:
                    raise ValueError(f"non-canonical ZIP compression: {info.filename}")
                if info.flag_bits & 0x1:
                    raise ValueError(f"encrypted ZIP member is forbidden: {info.filename}")
                if info.filename.endswith("/"):
                    if not stat.S_ISDIR(raw_mode) or not info.is_dir():
                        raise ValueError(f"ZIP directory type mismatch: {info.filename}")
                    if not (info.external_attr & 0x10):
                        raise ValueError(f"ZIP directory DOS attribute missing: {info.filename}")
                    if bundle.read(info):
                        raise ValueError(f"ZIP directory contains data: {info.filename}")
                else:
                    if not stat.S_ISREG(raw_mode) or info.is_dir():
                        raise ValueError(f"ZIP payload must be a regular file: {info.filename}")
                    observed_payload[PurePosixPath(info.filename).name] = bundle.read(info)
    else:
        if archive.read_bytes()[: len(GZIP_HEADER)] != GZIP_HEADER:
            raise ValueError("non-canonical gzip header")
        with tarfile.open(archive, mode="r:gz") as bundle:
            actual = []
            for info in bundle.getmembers():
                _safe_member(info.name)
                name = f"{info.name}/" if info.isdir() and not info.name.endswith("/") else info.name
                actual.append((name, info.mode & 0o777))
                expected_mode = expected_modes.get(name)
                if expected_mode is None or info.mode != expected_mode:
                    raise ValueError(f"non-canonical TAR permissions: {info.name}")
                if info.mtime != FIXED_MTIME or info.uid != 0 or info.gid != 0:
                    raise ValueError(f"non-deterministic TAR metadata: {info.name}")
                if info.uname or info.gname or info.pax_headers:
                    raise ValueError(f"non-canonical TAR metadata: {info.name}")
                if not (info.isdir() or info.isfile()):
                    raise ValueError(f"unsupported TAR member type: {info.name}")
                if info.isfile():
                    handle = bundle.extractfile(info)
                    if handle is None:
                        raise ValueError(f"TAR payload cannot be read: {info.name}")
                    observed_payload[PurePosixPath(info.name).name] = handle.read()
    if actual != expected:
        raise ValueError(f"archive inventory mismatch: expected {expected!r}, got {actual!r}")
    if expected_payload is not None and observed_payload != expected_payload:
        raise ValueError("archived payload bytes do not match the release inputs")


def extract_archive(*, archive: Path, output_dir: Path, version: str, target: str) -> Path:
    verify_archive(archive=archive, version=version, target=target)
    if output_dir.exists():
        raise ValueError(f"refusing non-fresh extraction directory: {output_dir}")
    output_dir.mkdir(parents=True)
    if target == WINDOWS_TARGET:
        with zipfile.ZipFile(archive) as bundle:
            members = [(info.filename, info.is_dir(), bundle.read(info)) for info in bundle.infolist()]
    else:
        members = []
        with tarfile.open(archive, mode="r:gz") as bundle:
            for info in bundle.getmembers():
                data = b""
                if info.isfile():
                    handle = bundle.extractfile(info)
                    if handle is None:
                        raise ValueError(f"TAR payload cannot be read: {info.name}")
                    data = handle.read()
                members.append((info.name, info.isdir(), data))
    for name, is_dir, data in members:
        _safe_member(name)
        destination = output_dir.joinpath(*PurePosixPath(name).parts)
        if is_dir:
            destination.mkdir()
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as handle:
                handle.write(data)
            if destination.name in {"tomorrowci", "tomorrowci.exe"}:
                destination.chmod(0o755)
    return output_dir / stage_name(version, target)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--source-root", type=Path, default=ROOT)
    create.add_argument("--binary", type=Path, required=True)
    create.add_argument("--output-dir", type=Path, required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--target", choices=sorted(ALLOWED_TARGETS), required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--target", choices=sorted(ALLOWED_TARGETS), required=True)
    extract = subparsers.add_parser("extract")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--output-dir", type=Path, required=True)
    extract.add_argument("--version", required=True)
    extract.add_argument("--target", choices=sorted(ALLOWED_TARGETS), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create_archive(
                source_root=args.source_root,
                binary=args.binary,
                output_dir=args.output_dir,
                version=args.version,
                target=args.target,
            )
            print(result)
        elif args.command == "verify":
            verify_archive(archive=args.archive, version=args.version, target=args.target)
            print(f"package-release: PASS: {args.archive}")
        else:
            result = extract_archive(
                archive=args.archive,
                output_dir=args.output_dir,
                version=args.version,
                target=args.target,
            )
            print(result)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"package-release: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
