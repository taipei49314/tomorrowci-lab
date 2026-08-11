#!/usr/bin/env python3

from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import promotion_preflight as preflight


class PromotionStateTests(unittest.TestCase):
    TAG_REF = "refs/tags/v0.2.0-alpha.1"
    TAG_OID = "a" * 40
    MARKER_REF = "refs/tags/tomorrowci-authorization/" + "b" * 64
    MARKER_OID = "c" * 40

    def state(self, observation: str) -> dict:
        return preflight.remote_state(
            observation,
            version_ref=self.TAG_REF,
            version_oid=self.TAG_OID,
            marker_ref=self.MARKER_REF,
            marker_oid=self.MARKER_OID,
        )

    def test_new_and_exact_idempotent_states(self) -> None:
        self.assertEqual(self.state("")["state"], "READY_FOR_ATOMIC_CREATE_ONLY")
        exact = (
            f"{self.TAG_OID}\t{self.TAG_REF}\n"
            f"{self.MARKER_OID}\t{self.MARKER_REF}\n"
        )
        self.assertEqual(self.state(exact)["state"], "IDEMPOTENT_EXACT_PAIR")
        self.assertEqual(self.state(exact)["status"], preflight.DISABLED_STATUS)

    def test_partial_mismatch_duplicate_and_unknown_fail_closed(self) -> None:
        bad = (
            f"{self.TAG_OID}\t{self.TAG_REF}\n",
            f"{'d' * 40}\t{self.TAG_REF}\n{self.MARKER_OID}\t{self.MARKER_REF}\n",
            f"{self.TAG_OID}\t{self.TAG_REF}\n{self.TAG_OID}\t{self.TAG_REF}\n",
            f"{self.TAG_OID}\trefs/tags/unexpected\n",
        )
        for observation in bad:
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                self.state(observation)

    def test_ci_run_must_be_exact_successful_default_push(self) -> None:
        source = "d" * 40
        run = {
            "conclusion": "success",
            "event": "push",
            "head_branch": "master",
            "head_repository": {"full_name": "owner/repo"},
            "head_sha": source,
            "id": 123,
            "path": ".github/workflows/ci.yml",
            "repository": {"full_name": "owner/repo"},
            "run_attempt": 2,
            "status": "completed",
        }
        preflight.inspect_ci_run(
            run,
            repository="owner/repo",
            source_sha=source,
            run_id="123",
            run_attempt="2",
        )
        for field, value in (("event", "pull_request"), ("conclusion", "failure"), ("head_sha", "e" * 40)):
            changed = copy.deepcopy(run)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                preflight.inspect_ci_run(
                    changed,
                    repository="owner/repo",
                    source_sha=source,
                    run_id="123",
                    run_attempt="2",
                )

    def test_publication_gate_is_permanent(self) -> None:
        with self.assertRaisesRegex(ValueError, "permanently disabled"):
            preflight.refuse_publication()


class PromotionWorkflowStaticTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]
    WORKFLOW = ROOT / ".github/workflows/protected-exact-byte-promotion.yml"

    def test_workflow_path_did_not_exist_at_any_historical_tag(self) -> None:
        tags = subprocess.run(
            ["git", "-C", str(self.ROOT), "tag", "--list"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        relative = self.WORKFLOW.relative_to(self.ROOT).as_posix()
        for tag in tags:
            result = subprocess.run(
                ["git", "-C", str(self.ROOT), "cat-file", "-e", f"{tag}:{relative}"],
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0, f"workflow exists at {tag}")

    def test_permissions_concurrency_and_permanent_gate(self) -> None:
        text = self.WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("\n  push:", text)
        self.assertIn("  actions: read\n  contents: read\n", text)
        self.assertIn("group: protected-exact-byte-promotion", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("environment: release", text)
        self.assertIn("contents: write", text)
        self.assertIn("packages: write", text)
        self.assertIn("assert-publication-disabled", text)
        self.assertNotIn("expected_policy_sha256:", text)
        self.assertNotIn("allowed_signers:", text.split("jobs:", 1)[0])
        for forbidden in (
            "cargo build",
            "docker build",
            "git push",
            "gh release create",
            "gh release upload",
            "docker push",
            "oras ",
            "skopeo ",
            "--clobber",
            "--force",
        ):
            self.assertNotIn(forbidden, text)

    def test_preflight_calls_real_existing_verifiers(self) -> None:
        text = self.WORKFLOW.read_text(encoding="utf-8")
        for invocation in (
            "scripts/candidate_manifest.py verify",
            "scripts/package_release.py verify",
            "scripts/oci_candidate.py verify",
            "scripts/external_authorization.py",
            "scripts/tag_promotion_attestation.py",
            "scripts/promotion_preflight.py inspect-remote-refs",
        ):
            self.assertIn(invocation, text)


if __name__ == "__main__":
    unittest.main()
