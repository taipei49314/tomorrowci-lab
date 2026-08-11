#!/usr/bin/env python3

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

import oci_candidate  # noqa: E402


SOURCE_SHA = "a" * 40
REPOSITORY = "example/tomorrowci-lab"
VERSION = "0.2.0-alpha.1"
RUN_ID = "123456"
RUN_ATTEMPT = 3
MATERIALS = (
    ("docker.io/library/rust", "1" * 64),
    ("docker.io/library/docker", "2" * 64),
    ("docker.io/library/debian", "3" * 64),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


class OciCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / "tomorrowci-oci-linux-amd64.tar"
        self.metadata = self.root / "build-metadata.json"
        self.containerfile = self.root / "Containerfile"
        self.provenance = self.root / "image-provenance.json"
        self.containerfile.write_text(
            "\n".join(
                f"FROM {source}@sha256:{material} AS stage{position}"
                for position, (source, material) in enumerate(MATERIALS)
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.files, self.index_descriptor = self._oci_files()
        self._write_archive(self.files)
        self._write_metadata(self.index_descriptor)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _oci_files(self, *, extra_manifest: bool = False) -> tuple[dict[str, bytes], dict]:
        layer = b"small deterministic layer"
        layer_digest = digest(layer)
        config = json_bytes(
            {
                "architecture": "amd64",
                "os": "linux",
                "config": {
                    "User": "65532:65532",
                    "Entrypoint": ["/usr/local/bin/tomorrowci"],
                    "Labels": {
                        "org.opencontainers.image.source": (
                            f"https://github.com/{REPOSITORY}"
                        ),
                        "org.opencontainers.image.revision": SOURCE_SHA,
                        "org.opencontainers.image.version": VERSION,
                    },
                },
                "rootfs": {"type": "layers", "diff_ids": [f"sha256:{digest(layer)}"]},
            }
        )
        config_digest = digest(config)
        manifest = json_bytes(
            {
                "schemaVersion": 2,
                "mediaType": oci_candidate.OCI_MANIFEST,
                "config": {
                    "mediaType": oci_candidate.OCI_CONFIG,
                    "digest": f"sha256:{config_digest}",
                    "size": len(config),
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "digest": f"sha256:{layer_digest}",
                        "size": len(layer),
                    }
                ],
            }
        )
        manifest_digest = digest(manifest)
        descriptors = [
            {
                "mediaType": oci_candidate.OCI_MANIFEST,
                "digest": f"sha256:{manifest_digest}",
                "size": len(manifest),
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ]
        if extra_manifest:
            descriptors.append(
                {
                    "mediaType": oci_candidate.OCI_MANIFEST,
                    "digest": f"sha256:{'f' * 64}",
                    "size": 1,
                    "platform": {"architecture": "unknown", "os": "unknown"},
                }
            )
        layout_index = json_bytes(
            {
                "schemaVersion": 2,
                "mediaType": oci_candidate.OCI_INDEX,
                "manifests": descriptors,
            }
        )
        files = {
            "oci-layout": json_bytes({"imageLayoutVersion": "1.0.0"}),
            "index.json": layout_index,
            f"blobs/sha256/{manifest_digest}": manifest,
            f"blobs/sha256/{config_digest}": config,
            f"blobs/sha256/{layer_digest}": layer,
        }
        return files, descriptors[0]

    def _write_archive(
        self,
        files: dict[str, bytes],
        *,
        special: list[tarfile.TarInfo] | None = None,
        duplicate: str | None = None,
        mtime: int = 0,
    ) -> None:
        with tarfile.open(self.archive, "w") as archive:
            for directory in ("blobs", "blobs/sha256"):
                info = tarfile.TarInfo(directory)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.mtime = mtime
                archive.addfile(info)
            for name in sorted(files):
                data = files[name]
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = mtime
                archive.addfile(info, io.BytesIO(data))
                if name == duplicate:
                    archive.addfile(info, io.BytesIO(data))
            for info in special or []:
                archive.addfile(info)

    def _write_metadata(self, descriptor: dict) -> None:
        materials = [
            {
                "uri": (
                    f"pkg:docker/{source.rsplit('/', 1)[-1]}?digest=sha256:{material}"
                    "&platform=linux%2Famd64"
                ),
                "digest": {"sha256": material},
            }
            for source, material in MATERIALS
        ]
        metadata = {
            "containerimage.digest": descriptor["digest"],
            "containerimage.descriptor": descriptor,
            "buildx.build.provenance": {
                "buildType": "https://mobyproject.org/buildkit@v1",
                "materials": materials,
                "invocation": {
                    "configSource": {"entryPoint": "Containerfile"},
                    "environment": {"platform": "linux/amd64"},
                    "parameters": {
                        "args": {
                            "build-arg:TCI_REVISION": SOURCE_SHA,
                            "build-arg:TCI_VERSION": VERSION,
                        },
                        "root": {
                            "configSource": {"path": "Containerfile"},
                            "request": {
                                "args": {
                                    "build-arg:TCI_REVISION": SOURCE_SHA,
                                    "build-arg:TCI_VERSION": VERSION,
                                    "vcs:revision": SOURCE_SHA,
                                    "vcs:source": f"https://github.com/{REPOSITORY}.git",
                                }
                            },
                        },
                    },
                },
            },
        }
        self.metadata.write_bytes(json_bytes(metadata))

    def _create(self) -> dict:
        return oci_candidate.create_candidate(
            archive=self.archive,
            metadata=self.metadata,
            containerfile=self.containerfile,
            provenance=self.provenance,
            version=VERSION,
            source_sha=SOURCE_SHA,
            repository=REPOSITORY,
            run_id=RUN_ID,
            run_attempt=RUN_ATTEMPT,
        )

    def _verify(self, **overrides: object) -> dict:
        arguments = {
            "archive": self.archive,
            "metadata": self.metadata,
            "containerfile": self.containerfile,
            "provenance": self.provenance,
            "expected_source_sha": SOURCE_SHA,
            "expected_repository": REPOSITORY,
            "expected_run_id": RUN_ID,
            "expected_run_attempt": RUN_ATTEMPT,
        }
        arguments.update(overrides)
        return oci_candidate.verify_candidate(**arguments)

    def test_create_and_verify_canonical_detached_provenance(self) -> None:
        created = self._create()
        verified = self._verify()
        self.assertEqual(verified, created)
        self.assertEqual(created["status"], oci_candidate.STATUS)
        self.assertFalse(created["promotion"]["authorized"])
        self.assertEqual(created["workflow"]["run_attempt"], RUN_ATTEMPT)
        self.assertEqual(
            created["workflow"]["run_url"],
            f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}",
        )
        self.assertEqual(
            created["build"]["metadata"]["sha256"],
            f"sha256:{digest(self.metadata.read_bytes())}",
        )
        self.assertEqual(
            created["oci"]["archive"]["sha256"],
            f"sha256:{digest(self.archive.read_bytes())}",
        )
        decoded = json.loads(self.provenance.read_text(encoding="utf-8"))
        self.assertEqual(
            self.provenance.read_bytes(), oci_candidate._canonical_bytes(decoded)
        )

    def test_pack_layout_is_reproducible_and_rejects_noncanonical_tar_metadata(self) -> None:
        archives = []
        for slot, timestamp in (("a", 123), ("b", 456)):
            layout = self.root / f"layout-{slot}"
            (layout / "blobs" / "sha256").mkdir(parents=True)
            for name, data in reversed(list(self.files.items())):
                path = layout / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                os.utime(path, (timestamp, timestamp))
            archive = self.root / f"canonical-{slot}.tar"
            oci_candidate.pack_layout(layout=layout, archive=archive)
            archives.append(archive)
        self.assertEqual(archives[0].read_bytes(), archives[1].read_bytes())
        with oci_candidate._OciArchive(archives[0]):
            pass

        self._write_archive(self.files, mtime=1)
        with self.assertRaisesRegex(ValueError, "metadata is not canonical"):
            self._create()

    def test_verifier_rejects_noncanonical_tar_carriers_and_trailing_bytes(self) -> None:
        canonical = self.archive.read_bytes()
        mutations = (
            ("trailing bytes", canonical + b"UNBOUND-TRAILING-BYTES"),
            ("extra zero record", canonical + bytes(oci_candidate.TAR_RECORD_SIZE)),
            ("compressed carrier", gzip.compress(canonical, mtime=0)),
        )
        for label, payload in mutations:
            with self.subTest(label):
                self.archive.write_bytes(payload)
                with self.assertRaisesRegex(
                    ValueError,
                    "canonical EOF length|canonical uncompressed USTAR",
                ):
                    self._create()
        self.archive.write_bytes(canonical)

    def test_pack_layout_rejects_extra_entries_and_existing_output(self) -> None:
        layout = self.root / "layout"
        (layout / "blobs" / "sha256").mkdir(parents=True)
        for name, data in self.files.items():
            path = layout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        output = self.root / "canonical.tar"
        output.write_bytes(b"existing")
        with self.assertRaisesRegex(ValueError, "must not already exist"):
            oci_candidate.pack_layout(layout=layout, archive=output)
        output.unlink()
        (layout / "unexpected").write_text("extra", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unexpected root inventory"):
            oci_candidate.pack_layout(layout=layout, archive=output)
        (layout / "unexpected").unlink()
        (layout / "ingest").mkdir()
        oci_candidate.pack_layout(layout=layout, archive=output)
        output.unlink()
        (layout / "ingest" / "partial").write_bytes(b"not committed")
        with self.assertRaisesRegex(ValueError, "real empty directory"):
            oci_candidate.pack_layout(layout=layout, archive=output)

    def test_rejects_mutated_blob_and_extra_blob(self) -> None:
        with self.subTest("content digest"):
            mutated = dict(self.files)
            layer_name = next(
                name
                for name in mutated
                if name.startswith("blobs/sha256/")
                and mutated[name] == b"small deterministic layer"
            )
            mutated[layer_name] = b"mutated layer"
            self._write_archive(mutated)
            with self.assertRaisesRegex(ValueError, "digest"):
                self._create()
        with self.subTest("unreferenced blob"):
            self._write_archive(self.files | {f"blobs/sha256/{digest(b'extra')}": b"extra"})
            with self.assertRaisesRegex(ValueError, "unreferenced"):
                self._create()

    def test_rejects_attached_or_multiple_manifests(self) -> None:
        files, descriptor = self._oci_files(extra_manifest=True)
        self._write_archive(files)
        self._write_metadata(descriptor)
        with self.assertRaisesRegex(ValueError, "detached provenance mode"):
            self._create()

    def test_rejects_traversal_symlink_duplicate_and_extra_member(self) -> None:
        cases: list[tuple[str, tarfile.TarInfo, str]] = []
        traversal = tarfile.TarInfo("../escape")
        traversal.size = 0
        cases.append(("traversal", traversal, "unsafe"))
        symlink = tarfile.TarInfo("blobs/sha256/link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../../index.json"
        cases.append(("symlink", symlink, "not a regular"))
        extra = tarfile.TarInfo("unexpected.txt")
        extra.size = 0
        cases.append(("extra", extra, "extra"))
        for name, special, message in cases:
            with self.subTest(name):
                self._write_archive(self.files, special=[special])
                with self.assertRaisesRegex(ValueError, message):
                    self._create()
        with self.subTest("duplicate"):
            self._write_archive(self.files, duplicate="index.json")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self._create()

    def test_rejects_provenance_mutation_wrong_attempt_and_duplicate_json(self) -> None:
        self._create()
        document = json.loads(self.provenance.read_text(encoding="utf-8"))
        document["promotion"]["authorized"] = True
        self.provenance.write_bytes(oci_candidate._canonical_bytes(document))
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._verify()

        document["promotion"]["authorized"] = False
        document["workflow"]["run_attempt"] = RUN_ATTEMPT + 1
        self.provenance.write_bytes(oci_candidate._canonical_bytes(document))
        with self.assertRaisesRegex(ValueError, "expected attempt"):
            self._verify()

        document["workflow"]["run_attempt"] = True
        self.provenance.write_bytes(oci_candidate._canonical_bytes(document))
        with self.assertRaisesRegex(ValueError, "strict integers"):
            self._verify(expected_run_attempt=None)

        self.provenance.write_text(
            '{"schema_version":1,"schema_version":1}\n',
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self._verify()

    def test_rejects_metadata_mutation_and_attempt_replay(self) -> None:
        self._create()
        metadata = json.loads(self.metadata.read_text(encoding="utf-8"))
        metadata["containerimage.digest"] = f"sha256:{'f' * 64}"
        self.metadata.write_bytes(json_bytes(metadata))
        with self.assertRaisesRegex(ValueError, "metadata digest"):
            self._verify()

        self._write_metadata(self.index_descriptor)
        with self.assertRaisesRegex(ValueError, "expected attempt"):
            self._verify(expected_run_attempt=RUN_ATTEMPT + 1)


if __name__ == "__main__":
    unittest.main()
