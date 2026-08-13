#!/usr/bin/env python3

from __future__ import annotations

import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from candidate_manifest import (
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    OCI_PAYLOAD,
    create_candidate,
    payload_names,
    verify_candidate,
)
from package_release import ZIP_EPOCH, create_archive, extract_archive, verify_archive

VERSION = "0.2.0-alpha.1"
SHA = "1" * 40
REPOSITORY = "taipei49314/tomorrowci-lab"
RUN_ID = "31447884019"
WORKFLOW_REF = (
    "taipei49314/tomorrowci-lab/.github/workflows/candidate.yml@refs/heads/master"
)


def write_canonical_windows_zip_with_nul_readme(archive: Path) -> None:
    root = f"tomorrowci-v{VERSION}-x86_64-pc-windows-msvc"
    visible_name = f"{root}/README.md"
    placeholder = f"{visible_name}Xhidden".encode()
    malicious = visible_name.encode() + b"\0hidden"
    entries = (
        (f"{root}/", stat.S_IFDIR | 0o755, b""),
        (f"{root}/tomorrowci.exe", stat.S_IFREG | 0o755, b"cli"),
        (placeholder.decode(), stat.S_IFREG | 0o644, b"readme"),
        (f"{root}/LICENSE", stat.S_IFREG | 0o644, b"license"),
        (f"{root}/CHANGELOG.md", stat.S_IFREG | 0o644, b"changes"),
    )
    with zipfile.ZipFile(
        archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as bundle:
        for name, mode, data in entries:
            info = zipfile.ZipInfo(name, ZIP_EPOCH)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (mode & 0xFFFF) << 16
            if name.endswith("/"):
                info.external_attr |= 0x10
            info.flag_bits |= 0x800
            bundle.writestr(info, data)
    data = archive.read_bytes()
    if len(placeholder) != len(malicious) or data.count(placeholder) != 2:
        raise AssertionError("ZIP test fixture did not contain two raw member names")
    archive.write_bytes(data.replace(placeholder, malicious))


class ReleaseCandidateTests(unittest.TestCase):
    def make_source(self, root: Path, *, windows: bool = False) -> tuple[Path, Path]:
        source = root / "source"
        source.mkdir()
        for name in ("README.md", "LICENSE", "CHANGELOG.md"):
            (source / name).write_text(f"{name}\n", encoding="utf-8", newline="\n")
        binary = source / ("tomorrowci.exe" if windows else "tomorrowci")
        binary.write_bytes(b"deterministic-cli-bytes\n")
        return source, binary

    def make_payload(self, dist: Path) -> None:
        dist.mkdir()
        for index, name in enumerate(payload_names(VERSION), start=1):
            (dist / name).write_bytes(f"payload-{index}-{name}\n".encode())

    def create_manifest(self, dist: Path) -> dict:
        return create_candidate(
            dist=dist,
            version=VERSION,
            source_sha=SHA,
            repository=REPOSITORY,
            source_ref="refs/heads/master",
            run_id=RUN_ID,
            run_attempt=1,
            workflow_ref=WORKFLOW_REF,
        )

    def test_unix_archive_is_reproducible_with_exact_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, binary = self.make_source(root)
            first = create_archive(
                source_root=source,
                binary=binary,
                output_dir=root / "first",
                version=VERSION,
                target="x86_64-unknown-linux-gnu",
            )
            for path in (source, *source.iterdir()):
                path.touch()
            second = create_archive(
                source_root=source,
                binary=binary,
                output_dir=root / "second",
                version=VERSION,
                target="x86_64-unknown-linux-gnu",
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            verify_archive(
                archive=first, version=VERSION, target="x86_64-unknown-linux-gnu"
            )
            forged = bytearray(first.read_bytes())
            forged[4] = 1
            first.write_bytes(forged)
            with self.assertRaisesRegex(ValueError, "gzip header"):
                verify_archive(
                    archive=first,
                    version=VERSION,
                    target="x86_64-unknown-linux-gnu",
                )

    def test_windows_archive_is_reproducible_with_same_top_level_layout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, binary = self.make_source(root, windows=True)
            first = create_archive(
                source_root=source,
                binary=binary,
                output_dir=root / "first",
                version=VERSION,
                target="x86_64-pc-windows-msvc",
            )
            second = create_archive(
                source_root=source,
                binary=binary,
                output_dir=root / "second",
                version=VERSION,
                target="x86_64-pc-windows-msvc",
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            verify_archive(
                archive=first, version=VERSION, target="x86_64-pc-windows-msvc"
            )
            extracted = extract_archive(
                archive=first,
                output_dir=root / "readback",
                version=VERSION,
                target="x86_64-pc-windows-msvc",
            )
            self.assertEqual(
                (extracted / "tomorrowci.exe").read_bytes(), binary.read_bytes()
            )

    def test_windows_zip_raw_nul_member_alias_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / f"tomorrowci-v{VERSION}-x86_64-pc-windows-msvc.zip"
            write_canonical_windows_zip_with_nul_readme(archive)
            with zipfile.ZipFile(archive) as bundle:
                readme = bundle.infolist()[2]
                self.assertTrue(readme.orig_filename.endswith("README.md\0hidden"))
                self.assertTrue(readme.filename.endswith("README.md"))
                self.assertEqual(readme.compress_type, zipfile.ZIP_DEFLATED)
            with self.assertRaisesRegex(ValueError, "unsafe ZIP member name"):
                verify_archive(
                    archive=archive,
                    version=VERSION,
                    target="x86_64-pc-windows-msvc",
                )
            with self.assertRaisesRegex(ValueError, "unsafe ZIP member name"):
                extract_archive(
                    archive=archive,
                    output_dir=root / "extracted",
                    version=VERSION,
                    target="x86_64-pc-windows-msvc",
                )

    def test_zip_symlink_payload_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive = Path(raw) / f"tomorrowci-v{VERSION}-x86_64-pc-windows-msvc.zip"
            root = f"tomorrowci-v{VERSION}-x86_64-pc-windows-msvc"
            with zipfile.ZipFile(
                archive, "w", compression=zipfile.ZIP_DEFLATED
            ) as bundle:
                for name, mode, data in (
                    (f"{root}/", stat.S_IFDIR | 0o755, b""),
                    (f"{root}/tomorrowci.exe", stat.S_IFLNK | 0o755, b"outside"),
                    (f"{root}/README.md", stat.S_IFREG | 0o644, b"readme"),
                    (f"{root}/LICENSE", stat.S_IFREG | 0o644, b"license"),
                    (f"{root}/CHANGELOG.md", stat.S_IFREG | 0o644, b"changes"),
                ):
                    info = zipfile.ZipInfo(name, ZIP_EPOCH)
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = mode << 16
                    if name.endswith("/"):
                        info.external_attr |= 0x10
                    bundle.writestr(info, data)
            with self.assertRaisesRegex(ValueError, "type/permissions"):
                verify_archive(
                    archive=archive,
                    version=VERSION,
                    target="x86_64-pc-windows-msvc",
                )

    def test_stored_zip_payload_fails_canonical_verification(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive = Path(raw) / f"tomorrowci-v{VERSION}-x86_64-pc-windows-msvc.zip"
            root = f"tomorrowci-v{VERSION}-x86_64-pc-windows-msvc"
            with zipfile.ZipFile(
                archive, "w", compression=zipfile.ZIP_STORED
            ) as bundle:
                for name, mode, data in (
                    (f"{root}/", stat.S_IFDIR | 0o755, b""),
                    (f"{root}/tomorrowci.exe", stat.S_IFREG | 0o755, b"cli"),
                    (f"{root}/README.md", stat.S_IFREG | 0o644, b"readme"),
                    (f"{root}/LICENSE", stat.S_IFREG | 0o644, b"license"),
                    (f"{root}/CHANGELOG.md", stat.S_IFREG | 0o644, b"changes"),
                ):
                    info = zipfile.ZipInfo(name, ZIP_EPOCH)
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = mode << 16
                    if name.endswith("/"):
                        info.external_attr |= 0x10
                    bundle.writestr(info, data)
            with self.assertRaisesRegex(ValueError, "ZIP compression"):
                verify_archive(
                    archive=archive,
                    version=VERSION,
                    target="x86_64-pc-windows-msvc",
                )

    def test_candidate_manifest_binds_exact_payload_source_and_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dist = Path(raw) / "dist"
            self.make_payload(dist)
            manifest = self.create_manifest(dist)
            self.assertFalse(manifest["promotion"]["authorized"])
            self.assertEqual(manifest["source"]["commit"], SHA)
            verified = verify_candidate(
                dist=dist,
                expected_source_sha=SHA,
                expected_repository=REPOSITORY,
                expected_run_id=RUN_ID,
                expected_run_attempt=1,
            )
            self.assertEqual(verified, manifest)
            self.assertEqual(
                manifest["workflow"]["run_url"],
                f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/1",
            )
            with self.assertRaisesRegex(ValueError, "workflow attempt"):
                verify_candidate(dist=dist, expected_run_attempt=2)
            self.assertEqual(
                {path.name for path in dist.iterdir()},
                {*payload_names(VERSION), MANIFEST_NAME, CHECKSUMS_NAME},
            )

    def test_candidate_inventory_requires_exact_oci_evidence_set(self) -> None:
        expected = {
            "Containerfile",
            "build-metadata.json",
            "image-provenance.json",
            "image-sbom.cdx.json",
            "image-vulnerabilities.json",
            "tomorrowci-oci-linux-amd64.tar",
        }
        self.assertEqual(set(OCI_PAYLOAD), expected)
        self.assertTrue(expected.issubset(payload_names(VERSION)))
        with tempfile.TemporaryDirectory() as raw:
            dist = Path(raw) / "dist"
            self.make_payload(dist)
            missing = dist / "image-provenance.json"
            original = missing.read_bytes()
            missing.unlink()
            with self.assertRaisesRegex(ValueError, "payload inventory mismatch"):
                self.create_manifest(dist)
            missing.write_bytes(original)
            (dist / "unexpected-oci-attestation.json").write_text(
                "{}\n", encoding="utf-8", newline="\n"
            )
            with self.assertRaisesRegex(ValueError, "payload inventory mismatch"):
                self.create_manifest(dist)

    def test_payload_mutation_and_unlisted_file_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dist = Path(raw) / "dist"
            self.make_payload(dist)
            self.create_manifest(dist)
            target = dist / payload_names(VERSION)[0]
            target.write_bytes(target.read_bytes() + b"mutation")
            with self.assertRaisesRegex(ValueError, "payload mismatch"):
                verify_candidate(dist=dist)
            target.write_bytes(target.read_bytes()[:-8])
            (dist / "unexpected.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "final inventory mismatch"):
                verify_candidate(dist=dist)

    def test_checksum_file_requires_canonical_lf_and_final_newline(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dist = Path(raw) / "dist"
            self.make_payload(dist)
            self.create_manifest(dist)
            sums = (dist / CHECKSUMS_NAME).read_bytes()
            (dist / CHECKSUMS_NAME).write_bytes(sums.replace(b"\n", b"\r\n"))
            with self.assertRaisesRegex(ValueError, "non-canonical encoding"):
                verify_candidate(dist=dist)
            (dist / CHECKSUMS_NAME).write_bytes(sums[:-1])
            with self.assertRaisesRegex(ValueError, "non-canonical encoding"):
                verify_candidate(dist=dist)

    def test_manifest_forgery_and_moving_ref_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dist = Path(raw) / "dist"
            self.make_payload(dist)
            with self.assertRaisesRegex(ValueError, "refs/heads/master"):
                create_candidate(
                    dist=dist,
                    version=VERSION,
                    source_sha=SHA,
                    repository=REPOSITORY,
                    source_ref="refs/heads/release",
                    run_id=RUN_ID,
                    run_attempt=1,
                    workflow_ref=WORKFLOW_REF,
                )
            manifest = self.create_manifest(dist)
            manifest["promotion"]["authorized"] = True
            (dist / MANIFEST_NAME).write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "explicitly unauthorized"):
                verify_candidate(dist=dist)

    def test_json_scalar_type_confusion_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            dist = Path(raw) / "dist"
            self.make_payload(dist)
            manifest = self.create_manifest(dist)
            manifest["schema_version"] = True
            (dist / MANIFEST_NAME).write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "schema identity"):
                verify_candidate(dist=dist)

            manifest["schema_version"] = 1
            manifest["workflow"]["run_attempt"] = True
            (dist / MANIFEST_NAME).write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "strict integers"):
                verify_candidate(dist=dist)

            manifest["workflow"]["run_attempt"] = 1
            manifest["promotion"]["authorized"] = 0
            (dist / MANIFEST_NAME).write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "explicitly unauthorized"):
                verify_candidate(dist=dist)


if __name__ == "__main__":
    unittest.main()
