#!/usr/bin/env python3

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

import external_observation as contract


class ExternalObservationTests(unittest.TestCase):
    LOG = b"run_id: 0123456789ab\n"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def record(
        self,
        target: str,
        engine: str,
        scan_exit: int | None = 0,
        step_exit: int = 0,
        phase: str = "complete",
    ) -> dict[str, object]:
        repository, commit, config = contract.EXPECTED[(target, engine)]
        log = self.root / f"{target}-{engine}.txt"
        log.write_bytes(self.LOG if scan_exit is not None else b"")
        return contract.create_record(
            argparse.Namespace(
                target_id=target,
                engine=engine,
                remote_repository=repository,
                remote_commit=commit,
                config_path=config,
                project_repository="taipei49314/tomorrowci-lab",
                project_source_sha="a" * 40,
                candidate_run_id=31467330932,
                candidate_run_attempt=1,
                candidate_manifest_sha256="sha256:" + "b" * 64,
                candidate_source_sha="a" * 40,
                oci_manifest_digest="sha256:" + "c" * 64,
                workflow_run_id=123,
                workflow_run_attempt=1,
                scan_attempted=scan_exit is not None,
                scan_exit=scan_exit,
                step_exit=step_exit,
                phase=phase,
                scan_log=log,
            )
        )

    def write_artifact(self, root: Path, record: dict[str, object]) -> None:
        root.mkdir(parents=True)
        transcript = self.LOG if record["scan"]["attempted"] else b""
        (root / "scan.txt").write_bytes(transcript)
        (root / "observation.json").write_bytes(contract.canonical_bytes(record))

    def write_downloaded_artifact(self, collection: Path, record: dict[str, object]) -> None:
        qualification = record["qualification"]
        workflow = record["workflow"]
        name = (
            f"raw-external-observation-{qualification['target_id']}-{qualification['engine']}"
            f"-attempt-{workflow['run_attempt']}-source-{workflow['source_sha']}"
        )
        self.write_artifact(collection / name, record)

    def test_six_pair_summary_is_diagnostic_not_authority(self) -> None:
        collection = self.root / "collection"
        collection.mkdir()
        for pair in sorted(contract.EXPECTED):
            self.write_downloaded_artifact(collection, self.record(*pair))
        summary = contract.build_summary(collection)
        self.assertEqual(summary["artifact_count"], 6)
        self.assertEqual(summary["status"], "ALL_QUALIFICATION_STEPS_EXITED_ZERO")
        self.assertIs(summary["qualification_authority"], False)

    def test_nonzero_exit_is_retained_without_becoming_success(self) -> None:
        record = self.record("node-helmet", "docker", 0, 2, "verify-run")
        self.assertEqual(record["status"], "QUALIFICATION_STEP_NONZERO")
        self.assertEqual(record["step"], {"exit_code": 2, "phase": "verify-run"})
        self.assertEqual(record["scan"]["exit_code"], 0)

    def test_unattempted_scan_retains_preflight_failure(self) -> None:
        record = self.record("node-helmet", "docker", None, 1, "preflight")
        self.assertEqual(record["status"], "QUALIFICATION_STEP_NONZERO")
        self.assertIs(record["scan"]["attempted"], False)
        self.assertIsNone(record["scan"]["exit_code"])

    def test_tampered_identity_is_rejected(self) -> None:
        root = self.root / "one"
        record = self.record("node-helmet", "docker")
        record["qualification"]["remote_commit"] = "b" * 40
        self.write_artifact(root, record)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            contract.load_record(root / "observation.json")

    def test_transcript_tamper_and_unknown_field_are_rejected(self) -> None:
        transcript_root = self.root / "transcript"
        self.write_artifact(transcript_root, self.record("node-helmet", "docker"))
        (transcript_root / "scan.txt").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(ValueError, "transcript read-back mismatch"):
            contract.load_record(transcript_root / "observation.json")

        field_root = self.root / "field"
        record = self.record("node-helmet", "docker")
        record["unexpected"] = True
        self.write_artifact(field_root, record)
        with self.assertRaisesRegex(ValueError, "top-level keys"):
            contract.load_record(field_root / "observation.json")

    def test_workflow_and_candidate_identity_mismatches_are_rejected(self) -> None:
        collection = self.root / "identity"
        collection.mkdir()
        for index, pair in enumerate(sorted(contract.EXPECTED)):
            record = self.record(*pair)
            if index == 5:
                record["workflow"]["run_id"] = 124
            self.write_downloaded_artifact(collection, record)
        with self.assertRaisesRegex(ValueError, "workflow identity"):
            contract.build_summary(collection)

        candidate_collection = self.root / "candidate-identity"
        candidate_collection.mkdir()
        for index, pair in enumerate(sorted(contract.EXPECTED)):
            record = self.record(*pair)
            if index == 5:
                record["candidate"]["run_id"] = 31467330933
            self.write_downloaded_artifact(candidate_collection, record)
        with self.assertRaisesRegex(ValueError, "candidate identity"):
            contract.build_summary(candidate_collection)

    def test_artifact_name_must_match_record(self) -> None:
        collection = self.root / "artifact-name"
        collection.mkdir()
        pairs = sorted(contract.EXPECTED)
        for index, pair in enumerate(pairs):
            record = self.record(*pair)
            if index == 5:
                expected_target, expected_engine = pair
                record["qualification"]["target_id"] = "node-helmet"
                record["qualification"]["engine"] = "docker"
                workflow = record["workflow"]
                name = (
                    f"raw-external-observation-{expected_target}-{expected_engine}"
                    f"-attempt-{workflow['run_attempt']}-source-{workflow['source_sha']}"
                )
                self.write_artifact(collection / name, record)
            else:
                self.write_downloaded_artifact(collection, record)
        with self.assertRaises(ValueError):
            contract.build_summary(collection)

    def test_incomplete_phase_cannot_claim_step_success(self) -> None:
        root = self.root / "phase"
        record = self.record("node-helmet", "docker")
        record["step"]["phase"] = "verify-run"
        self.write_artifact(root, record)
        with self.assertRaisesRegex(ValueError, "completion phase"):
            contract.load_record(root / "observation.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
