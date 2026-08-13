#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import promotion_preflight as preflight


def write_nul_suffixed_member(
    archive: Path, *, visible_name: str, payload: bytes
) -> None:
    """Write the same NUL-suffixed raw name in local and central headers."""

    placeholder = f"{visible_name}Xhidden".encode()
    malicious = visible_name.encode() + b"\0hidden"
    entry = zipfile.ZipInfo(placeholder.decode())
    entry.create_system = 3
    entry.external_attr = (stat.S_IFREG | 0o600) << 16
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(entry, payload)
    data = archive.read_bytes()
    if len(placeholder) != len(malicious) or data.count(placeholder) != 2:
        raise AssertionError("ZIP test fixture did not contain two raw member names")
    archive.write_bytes(data.replace(placeholder, malicious))


class PromotionPlatformTests(unittest.TestCase):
    REPOSITORY = "owner/repo"
    SOURCE = "d" * 40
    CANDIDATE_MANIFEST = "sha256:" + "a" * 64
    OCI_MANIFEST = "sha256:" + "b" * 64
    PLATFORM_RUN_ID = 456
    PLATFORM_ATTEMPT = 2
    CANDIDATE_RUN_ID = 123
    CANDIDATE_ATTEMPT = 1

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run = {
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_branch": "master",
            "head_repository": {"full_name": self.REPOSITORY},
            "head_sha": self.SOURCE,
            "id": self.PLATFORM_RUN_ID,
            "name": "platform-qualification",
            "path": preflight.PLATFORM_WORKFLOW_PATH,
            "repository": {"full_name": self.REPOSITORY},
            "run_attempt": self.PLATFORM_ATTEMPT,
            "status": "completed",
        }
        self.api_artifacts = []
        self.identity_artifacts = []
        for index, spec in enumerate(
            preflight._platform_artifact_specs(self.PLATFORM_ATTEMPT, self.SOURCE),
            start=1,
        ):
            digest = "sha256:" + f"{index:064x}"
            artifact_id = 1000 + index
            self.api_artifacts.append(
                {
                    "archive_download_url": (
                        f"https://api.github.com/repos/{self.REPOSITORY}/actions/"
                        f"artifacts/{artifact_id}/zip"
                    ),
                    "digest": digest,
                    "expired": False,
                    "id": artifact_id,
                    "name": spec["name"],
                    "size_in_bytes": 2000 + index,
                    "workflow_run": {
                        "head_branch": "master",
                        "head_sha": self.SOURCE,
                        "id": self.PLATFORM_RUN_ID,
                    },
                }
            )
            self.identity_artifacts.append(
                {
                    "archive_sha256": digest,
                    "archive_size": 2000 + index,
                    "artifact_id": artifact_id,
                    **spec,
                }
            )
        self.artifact_metadata = {
            "artifacts": self.api_artifacts,
            "total_count": len(self.api_artifacts),
        }
        self.identity = {
            "artifacts": self.identity_artifacts,
            "candidate": {
                "manifest_sha256": self.CANDIDATE_MANIFEST,
                "oci_manifest_digest": self.OCI_MANIFEST,
                "run_attempt": self.CANDIDATE_ATTEMPT,
                "run_id": self.CANDIDATE_RUN_ID,
                "source_sha": self.SOURCE,
            },
            "kind": preflight.PLATFORM_INPUT_KIND,
            "project": {
                "repository": self.REPOSITORY,
                "source_ref": "refs/heads/master",
                "source_sha": self.SOURCE,
            },
            "schema_version": 1,
            "status": preflight.platform_qualification.STATUS,
            "workflow": {
                "conclusion": "success",
                "path": preflight.PLATFORM_WORKFLOW_PATH,
                "run_attempt": self.PLATFORM_ATTEMPT,
                "run_id": self.PLATFORM_RUN_ID,
            },
        }
        self.identity_digest = preflight._sha256(
            preflight.canonical_bytes(self.identity)
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def inspect(
        self, *, run: dict | None = None, artifacts: dict | None = None
    ) -> dict:
        return preflight.inspect_platform_api(
            self.run if run is None else run,
            self.artifact_metadata if artifacts is None else artifacts,
            repository=self.REPOSITORY,
            source_sha=self.SOURCE,
            run_id=str(self.PLATFORM_RUN_ID),
            run_attempt=str(self.PLATFORM_ATTEMPT),
            candidate_run_id=str(self.CANDIDATE_RUN_ID),
            candidate_run_attempt=str(self.CANDIDATE_ATTEMPT),
            candidate_manifest_sha256=self.CANDIDATE_MANIFEST,
            oci_manifest_digest=self.OCI_MANIFEST,
            expected_identity_sha256=self.identity_digest,
        )

    def test_exact_platform_run_and_seven_artifact_identities(self) -> None:
        identity = self.inspect()
        self.assertEqual(identity, self.identity)
        self.assertEqual(len(identity["artifacts"]), 7)
        self.assertEqual(
            {
                item["scope"]
                for item in identity["artifacts"]
                if item["role"] == "qualification"
            },
            set(preflight.PLATFORM_IDS),
        )

    def test_missing_duplicate_expired_and_run_drift_fail_closed(self) -> None:
        missing = copy.deepcopy(self.artifact_metadata)
        missing["artifacts"].pop()
        missing["total_count"] -= 1
        duplicate = copy.deepcopy(self.artifact_metadata)
        duplicate["artifacts"].append(copy.deepcopy(duplicate["artifacts"][0]))
        duplicate["total_count"] += 1
        expired = copy.deepcopy(self.artifact_metadata)
        expired["artifacts"][0]["expired"] = True
        bad_run = copy.deepcopy(self.run)
        bad_run["head_sha"] = "e" * 40
        cases = (
            (self.run, missing),
            (self.run, duplicate),
            (self.run, expired),
            (bad_run, self.artifact_metadata),
        )
        for run, artifacts in cases:
            with (
                self.subTest(run=run, count=artifacts["total_count"]),
                self.assertRaises(ValueError),
            ):
                self.inspect(run=run, artifacts=artifacts)

    def test_dispatch_identity_digest_cannot_be_recomputed_from_drift(self) -> None:
        drift = copy.deepcopy(self.artifact_metadata)
        drift["artifacts"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "canonical identity digest mismatch"):
            self.inspect(artifacts=drift)

    def test_recursive_platform_zip_extraction_rejects_aliases(self) -> None:
        archive = self.root / "platform.zip"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("metadata/post-state.json", b"{}\n")
            package.writestr("platform-record.json", b"{}\n")
        destination = self.root / "platform"
        preflight.safe_extract_platform_artifact(archive, destination)
        self.assertEqual(
            (destination / "metadata" / "post-state.json").read_bytes(), b"{}\n"
        )

        traversal = self.root / "traversal.zip"
        with zipfile.ZipFile(traversal, "w") as package:
            package.writestr("../escape", b"x")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            preflight.safe_extract_platform_artifact(
                traversal, self.root / "traversal-output"
            )

        symlink = self.root / "symlink.zip"
        entry = zipfile.ZipInfo("link")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(symlink, "w") as package:
            package.writestr(entry, b"target")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            preflight.safe_extract_platform_artifact(
                symlink, self.root / "symlink-output"
            )

    def test_exact_and_recursive_extract_reject_raw_nul_suffix_aliases(self) -> None:
        observation = self.root / "nul-observation.zip"
        write_nul_suffixed_member(
            observation, visible_name="readback-pass.txt", payload=b"PASS\n"
        )
        with zipfile.ZipFile(observation) as package:
            entry = package.infolist()[0]
            self.assertEqual(entry.filename, "readback-pass.txt")
            self.assertEqual(entry.orig_filename, "readback-pass.txt\0hidden")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            preflight.safe_extract_platform_observation(
                observation, self.root / "nul-observation-output", role="readback"
            )

        artifact = self.root / "nul-platform.zip"
        write_nul_suffixed_member(
            artifact, visible_name="metadata/post-state.json", payload=b"{}\n"
        )
        with self.assertRaisesRegex(ValueError, "unsafe"):
            preflight.safe_extract_platform_artifact(
                artifact, self.root / "nul-platform-output"
            )

    def _write_observation(
        self, root: Path, *, role: str, scope: str, mutate: bool = False
    ) -> None:
        root.mkdir(parents=True)
        name = (
            "candidate-binding-pass.txt"
            if role == "candidate-binding"
            else "readback-pass.txt"
        )
        data = preflight._platform_observation_bytes(
            self.identity, role=role, scope=scope
        )
        if mutate:
            data = data.replace(b"status: PASS", b"status: FAIL_ONLY")
        (root / name).write_bytes(data)

    def _write_consumption_fixture(self) -> tuple[Path, Path, Path, Path, Path]:
        identity_path = self.root / "platform-identity.json"
        identity_path.write_bytes(preflight.canonical_bytes(self.identity))
        artifacts_root = self.root / "platform-artifacts"
        observations_root = self.root / "platform-observations"
        candidate_dist = self.root / "candidate-dist"
        fixture_source = self.root / "fixture"
        artifacts_root.mkdir()
        (observations_root / "readback").mkdir(parents=True)
        candidate_dist.mkdir()
        fixture_source.mkdir()
        self._write_observation(
            observations_root / "candidate-binding",
            role="candidate-binding",
            scope="candidate",
        )
        for platform_id in preflight.PLATFORM_IDS:
            spec = preflight.platform_qualification.PLATFORMS[platform_id]
            artifact = artifacts_root / platform_id
            (artifact / "metadata").mkdir(parents=True)
            (artifact / "metadata" / "post-state.json").write_bytes(
                preflight.platform_qualification.canonical_json_bytes(
                    {"containers": [], "volumes": []}
                )
            )
            record = {
                "candidate": {
                    "manifest_sha256": self.CANDIDATE_MANIFEST,
                    "oci_manifest_digest": self.OCI_MANIFEST,
                    "run_attempt": self.CANDIDATE_ATTEMPT,
                    "run_id": self.CANDIDATE_RUN_ID,
                    "source_sha": self.SOURCE,
                },
                "capture_sha256": "sha256:" + "1" * 64,
                "evidence": {"replay_count": 2},
                "platform": {
                    "engine": {
                        "context": spec.engine_context,
                        "os_type": "linux",
                        "provider": spec.provider,
                        "server_version": "1",
                        "version_output": "1",
                    },
                    "platform_id": platform_id,
                    "runner": {
                        "arch": spec.runner_arch,
                        "environment": "self-hosted",
                        "os": spec.runner_os,
                    },
                },
                "workflow": {
                    "repository": self.REPOSITORY,
                    "run_attempt": self.PLATFORM_ATTEMPT,
                    "run_id": self.PLATFORM_RUN_ID,
                    "source_ref": "refs/heads/master",
                    "source_sha": self.SOURCE,
                },
            }
            (artifact / preflight.platform_qualification.RECORD_NAME).write_bytes(
                preflight.platform_qualification.canonical_json_bytes(record)
            )
            self._write_observation(
                observations_root / "readback" / platform_id,
                role="readback",
                scope=platform_id,
            )
        return (
            identity_path,
            artifacts_root,
            observations_root,
            candidate_dist,
            fixture_source,
        )

    def test_consumption_binds_provider_engine_post_clean_and_readback(self) -> None:
        inputs = self._write_consumption_fixture()
        with patch("platform_qualification.verify_artifact") as verifier:
            consumption = preflight.verify_platform_consumption(
                identity_path=inputs[0],
                artifacts_root=inputs[1],
                observations_root=inputs[2],
                candidate_dist=inputs[3],
                fixture_source=inputs[4],
            )
        self.assertEqual(verifier.call_count, len(preflight.PLATFORM_IDS))
        self.assertEqual(
            [row["platform_id"] for row in consumption["platforms"]],
            list(preflight.PLATFORM_IDS),
        )

        platform_id = preflight.PLATFORM_IDS[0]
        record_path = (
            inputs[1] / platform_id / preflight.platform_qualification.RECORD_NAME
        )
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["platform"]["engine"]["provider"] = "substituted-provider"
        record_path.write_bytes(
            preflight.platform_qualification.canonical_json_bytes(record)
        )
        with (
            patch("platform_qualification.verify_artifact"),
            self.assertRaisesRegex(ValueError, "consumption row mismatch"),
        ):
            preflight.verify_platform_consumption(
                identity_path=inputs[0],
                artifacts_root=inputs[1],
                observations_root=inputs[2],
                candidate_dist=inputs[3],
                fixture_source=inputs[4],
            )

    def test_post_clean_or_readback_drift_fails(self) -> None:
        inputs = self._write_consumption_fixture()
        platform_id = preflight.PLATFORM_IDS[0]
        post = inputs[1] / platform_id / "metadata" / "post-state.json"
        post.write_bytes(
            preflight.platform_qualification.canonical_json_bytes(
                {"containers": ["unexpected"], "volumes": []}
            )
        )
        with (
            patch("platform_qualification.verify_artifact"),
            self.assertRaisesRegex(ValueError, "empty post-state"),
        ):
            preflight.verify_platform_consumption(
                identity_path=inputs[0],
                artifacts_root=inputs[1],
                observations_root=inputs[2],
                candidate_dist=inputs[3],
                fixture_source=inputs[4],
            )

        post.write_bytes(
            preflight.platform_qualification.canonical_json_bytes(
                {"containers": [], "volumes": []}
            )
        )
        readback = inputs[2] / "readback" / platform_id / "readback-pass.txt"
        readback.write_bytes(
            readback.read_bytes().replace(b"status: PASS", b"status: FAIL")
        )
        with (
            patch("platform_qualification.verify_artifact"),
            self.assertRaisesRegex(ValueError, "observation identity mismatch"),
        ):
            preflight.verify_platform_consumption(
                identity_path=inputs[0],
                artifacts_root=inputs[1],
                observations_root=inputs[2],
                candidate_dist=inputs[3],
                fixture_source=inputs[4],
            )


if __name__ == "__main__":
    unittest.main()
