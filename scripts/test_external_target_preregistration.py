#!/usr/bin/env python3
"""Offline negative and schema tests for Phase-7 target preregistration."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import external_target_preregistration as contract
from test_config_schema import load_schema, validate_fixture

SOURCE_DIR = contract.ROOT / "docs" / "qualification" / "external-targets"


class ExternalTargetPreregistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        destination = self.root / "docs" / "qualification" / "external-targets"
        destination.parent.mkdir(parents=True)
        shutil.copytree(SOURCE_DIR, destination)
        self.preregistration = destination / "preregistration-v1.json"
        self.original_preregistration = self.preregistration.read_bytes()

    def _document(self) -> dict:
        return json.loads(self.preregistration.read_text(encoding="utf-8"))

    def _write_document(self, value: dict) -> None:
        self.preregistration.write_bytes(contract.canonical_json_bytes(value))

    def _target(self, value: dict, target_id: str) -> dict:
        return next(target for target in value["targets"] if target["id"] == target_id)

    def _rewrite_config(self, target_id: str, engine: str, mutate) -> None:
        document = self._document()
        target = self._target(document, target_id)
        reference = target["configs"][engine]
        config_path = self.root.joinpath(*Path(reference["path"]).parts)
        config = json.loads(config_path.read_text(encoding="utf-8"))
        mutate(config)
        raw = contract.canonical_json_bytes(config)
        config_path.write_bytes(raw)
        reference["sha256"] = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        self._write_document(document)

    def test_repository_contract_and_all_configs_validate_without_execution(
        self,
    ) -> None:
        before = sorted(
            path.relative_to(self.root).as_posix()
            for path in self.root.rglob("*")
            if path.is_file()
        )
        verified = contract.verify_preregistration(self.preregistration, self.root)
        after = sorted(
            path.relative_to(self.root).as_posix()
            for path in self.root.rglob("*")
            if path.is_file()
        )
        self.assertEqual(verified.status, "NOT_RUN")
        self.assertEqual(
            verified.sha256,
            "sha256:1f9dee08d03f5f07b8c7f4396d6a0d3ee3aeb2b3071914e26d0a32f6e8b79ace",
        )
        self.assertRegex(
            verified.infrastructure_amendment_sha256, r"^sha256:[0-9a-f]{64}$"
        )
        self.assertEqual(
            verified.failed_observation_sha256,
            "sha256:80f0ac842a1ea84547771c06d12e621e2cf5af2374b8160af5ff7169bb881c6f",
        )
        self.assertEqual(verified.target_ids, tuple(contract.EXPECTED_TARGET_ORDER))
        self.assertEqual(len(verified.config_sha256), 6)
        self.assertEqual(before, after)
        self.assertFalse((self.root / ".tomorrowci").exists())

        schema = load_schema()
        self.assertEqual(schema["$id"], "https://tomorrowci.dev/schemas/config-v1.json")
        for config_path in sorted(
            (self.preregistration.parent / "configs").glob("*.json")
        ):
            raw = config_path.read_bytes()
            config = json.loads(raw)
            self.assertEqual(
                raw, contract.canonical_json_bytes(config), config_path.name
            )
            validate_fixture(config, schema)

    def test_rejects_amendment_or_failed_observation_rewrite(self) -> None:
        amendment = self.root.joinpath(*contract.INFRASTRUCTURE_AMENDMENT.parts)
        original_amendment = amendment.read_bytes()
        value = json.loads(original_amendment)
        value["change"]["history"] = True
        amendment.write_bytes(contract.canonical_json_bytes(value))
        with self.assertRaisesRegex(ValueError, "infrastructure amendment change"):
            contract.verify_preregistration(self.preregistration, self.root)

        amendment.write_bytes(original_amendment)
        observation = self.root.joinpath(*contract.FAILED_OBSERVATION.parts)
        value = json.loads(observation.read_bytes())
        value["failure"]["artifact_uploaded"] = True
        observation.write_bytes(contract.canonical_json_bytes(value))
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_rejects_duplicate_unknown_and_noncanonical_json(self) -> None:
        duplicate = self.original_preregistration.replace(
            b'{\n  "candidate_binding":',
            b'{\n  "status": "NOT_RUN",\n  "candidate_binding":',
            1,
        )
        cases = []
        cases.append(("duplicate", duplicate, "duplicate JSON key"))

        unknown = self._document()
        unknown["unexpected"] = True
        cases.append(
            (
                "unknown",
                contract.canonical_json_bytes(unknown),
                "unexpected schema",
            )
        )
        cases.append(
            (
                "bom",
                b"\xef\xbb\xbf" + self.original_preregistration,
                "without BOM",
            )
        )
        cases.append(
            (
                "crlf",
                self.original_preregistration.replace(b"\n", b"\r\n"),
                "LF line endings",
            )
        )
        for name, raw, message in cases:
            with self.subTest(name=name):
                self.preregistration.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, message):
                    contract.verify_preregistration(self.preregistration, self.root)
                self.preregistration.write_bytes(self.original_preregistration)

    def test_rejects_moving_ref_and_syntactically_valid_target_replacement(
        self,
    ) -> None:
        moving = self._document()
        self._target(moving, "python-azure-flask")["source"]["commit"] = "main"
        self._write_document(moving)
        with self.assertRaisesRegex(ValueError, "moving ref"):
            contract.verify_preregistration(self.preregistration, self.root)

        self.preregistration.write_bytes(self.original_preregistration)
        replacement = self._document()
        source = self._target(replacement, "python-azure-flask")["source"]
        source.update(
            {
                "commit": "a" * 40,
                "repository": "different-owner/different-repository",
                "tree": "b" * 40,
                "url": "https://github.com/different-owner/different-repository",
            }
        )
        self._write_document(replacement)
        with self.assertRaisesRegex(ValueError, "frozen source|replacement"):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_rejects_missing_lock_and_dependency_axis_overclaim(self) -> None:
        missing_lock = self._document()
        self._target(missing_lock, "node-helmet")["dependency_policy"]["lockfiles"] = []
        self._write_document(missing_lock)
        with self.assertRaisesRegex(ValueError, "requires an exact lockfile"):
            contract.verify_preregistration(self.preregistration, self.root)

        self.preregistration.write_bytes(self.original_preregistration)
        overclaim = self._document()
        self._target(overclaim, "python-azure-flask")["dependency_policy"][
            "axis_claim"
        ] = "INCLUDED"
        self._write_document(overclaim)
        with self.assertRaisesRegex(ValueError, "overclaim"):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_rejects_post_selection_rationale_rewrite(self) -> None:
        rewritten = self._document()
        self._target(rewritten, "node-helmet")["rationale"] = (
            "Replacement rationale written after observing a result."
        )
        self._write_document(rewritten)
        with self.assertRaisesRegex(ValueError, "frozen rationale.*changed"):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_rejects_negative_zero_as_canonical_float_drift(self) -> None:
        self._rewrite_config(
            "python-azure-flask",
            "docker",
            lambda config: config["policy"]["fail_if"].update(
                {"blocked_ratio_above": -0.0}
            ),
        )
        with self.assertRaisesRegex(
            ValueError, "docker target config contract.*blocked_ratio_above.*changed"
        ):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_rejects_engine_drift_even_when_reference_digest_is_updated(self) -> None:
        self._rewrite_config(
            "node-helmet",
            "podman",
            lambda config: config["sandbox"].update({"engine": "docker"}),
        )
        with self.assertRaisesRegex(
            ValueError, "podman target config contract.*engine"
        ):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_rejects_config_drift_even_when_reference_digest_is_updated(self) -> None:
        self._rewrite_config(
            "rust-human-panic",
            "podman",
            lambda config: config["execution"].update({"timeout_seconds": 901}),
        )
        with self.assertRaisesRegex(
            ValueError, "podman target config contract.*timeout_seconds"
        ):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_rejects_config_unknown_field_after_digest_rebind(self) -> None:
        self._rewrite_config(
            "python-azure-flask",
            "docker",
            lambda config: config["sandbox"].update({"privileged": False}),
        )
        with self.assertRaisesRegex(ValueError, "unexpected schema"):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_rejects_non_not_run_status_and_tree_limit_overrun(self) -> None:
        status = self._document()
        status["status"] = "PASS"
        self._write_document(status)
        with self.assertRaisesRegex(ValueError, "must remain version 1 NOT_RUN"):
            contract.verify_preregistration(self.preregistration, self.root)

        self.preregistration.write_bytes(self.original_preregistration)
        oversized = self._document()
        self._target(oversized, "node-helmet")["tree_inventory"]["blob_count"] = 10001
        self._write_document(oversized)
        with self.assertRaisesRegex(ValueError, "file-count limit"):
            contract.verify_preregistration(self.preregistration, self.root)

    def test_configs_are_identical_per_target_except_for_engine(self) -> None:
        document = self._document()
        for target in document["targets"]:
            values = {}
            for engine in ("docker", "podman"):
                path = self.root.joinpath(
                    *Path(target["configs"][engine]["path"]).parts
                )
                values[engine] = json.loads(path.read_text(encoding="utf-8"))
            docker = copy.deepcopy(values["docker"])
            podman = copy.deepcopy(values["podman"])
            self.assertEqual(docker["sandbox"]["engine"], "docker")
            self.assertEqual(podman["sandbox"]["engine"], "podman")
            docker["sandbox"]["engine"] = "ENGINE"
            podman["sandbox"]["engine"] = "ENGINE"
            self.assertEqual(docker, podman, target["id"])

    def test_workflow_retains_raw_failures_without_softening_result(self) -> None:
        workflow = (contract.ROOT / ".github/workflows/external-qualification.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("Upload raw target observation even when qualification fails", workflow)
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertIn("name: raw-external-observation-${{ matrix.target_id }}", workflow)
        self.assertIn("2>&1 | tee \"$scan_log\"", workflow)
        self.assertIn('scan_status="${PIPESTATUS[0]}"', workflow)
        self.assertIn("scripts/external_observation.py\" create", workflow)
        self.assertIn("if [ \"$scan_status\" -ne 0 ]; then", workflow)
        self.assertIn("observation-readback:", workflow)
        self.assertIn("qualification_authority", (contract.ROOT / "scripts/external_observation.py").read_text(encoding="utf-8"))
        self.assertNotIn("continue-on-error", workflow)
        self.assertLess(
            workflow.index("Upload raw target observation even when qualification fails"),
            workflow.index("Upload isolated target and engine evidence"),
        )


if __name__ == "__main__":
    unittest.main()
