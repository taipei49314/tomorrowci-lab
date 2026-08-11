#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
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

    def test_oci_input_binds_only_authoritative_manifest_digest(self) -> None:
        authoritative = "sha256:" + "1" * 64
        decoy = "sha256:" + "2" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image-provenance.json"
            path.write_text(
                json.dumps(
                    {
                        "build": {"decoy_digest": decoy},
                        "oci": {"manifest": {"digest": authoritative}},
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                preflight.inspect_oci_manifest_digest(path, authoritative),
                authoritative,
            )
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                preflight.inspect_oci_manifest_digest(path, decoy)

    def test_oci_manifest_parse_rejects_duplicate_digest_keys(self) -> None:
        digest = "sha256:" + "1" * 64
        replacement = "sha256:" + "2" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image-provenance.json"
            path.write_text(
                '{"oci":{"manifest":{"digest":"'
                + digest
                + '","digest":"'
                + replacement
                + '"}}}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                preflight.inspect_oci_manifest_digest(path, digest)


class AuthorizationMarkerTests(unittest.TestCase):
    AUTHORIZATION_ID = "b" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        self._git("init", "-q")
        self._git("config", "user.name", "Fixture")
        self._git("config", "user.email", "fixture@example.invalid")
        (self.repo / "tracked.txt").write_text("candidate\n", encoding="utf-8")
        self._git("add", "tracked.txt")
        self._git("commit", "-q", "-m", "candidate")
        self.commit = self._git("rev-parse", "HEAD")
        self.marker_name = f"tomorrowci-authorization/{self.AUTHORIZATION_ID}"
        self.marker_ref = f"refs/tags/{self.marker_name}"
        self._annotated(self.marker_name, self.commit)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def _annotated(self, name: str, target: str) -> None:
        self._git(
            "tag",
            "--no-sign",
            "--annotate",
            "--message",
            f"Consume authorization {self.AUTHORIZATION_ID}",
            name,
            target,
        )

    def inspect(self) -> dict:
        return preflight.inspect_authorization_marker(
            git_repo=self.repo,
            marker_ref=self.marker_ref,
            candidate_source_sha=self.commit,
            authorization_id=self.AUTHORIZATION_ID,
        )

    def test_accepts_exact_direct_annotated_marker(self) -> None:
        identity = self.inspect()
        self.assertEqual(identity["internal_name"], self.marker_name)
        self.assertEqual(identity["target_sha"], self.commit)
        self.assertEqual(identity["peeled_commit"], self.commit)

    def test_rejects_lightweight_marker(self) -> None:
        self._git("tag", "-d", self.marker_name)
        self._git("tag", self.marker_name, self.commit)
        with self.assertRaisesRegex(ValueError, "lightweight tag"):
            self.inspect()

    def test_rejects_marker_targeting_another_commit(self) -> None:
        self._git("tag", "-d", self.marker_name)
        (self.repo / "other.txt").write_text("other\n", encoding="utf-8")
        self._git("add", "other.txt")
        self._git("commit", "-q", "-m", "other")
        other = self._git("rev-parse", "HEAD")
        self._annotated(self.marker_name, other)
        with self.assertRaisesRegex(ValueError, "exact candidate commit"):
            self.inspect()

    def test_rejects_tag_object_with_an_alias_internal_name(self) -> None:
        self._annotated("authorization-alias", self.commit)
        alias_oid = self._git("rev-parse", "refs/tags/authorization-alias")
        self._git("update-ref", self.marker_ref, alias_oid)
        with self.assertRaisesRegex(ValueError, "internal name"):
            self.inspect()


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
        self.assertIn("inspect-authorization-marker", text)
        self.assertIn("inspect-oci-manifest", text)
        self.assertIn("git tag --no-sign --annotate", text)
        self.assertNotIn("state_artifact:", text)
        self.assertNotIn('grep -Fq "$OCI_MANIFEST_DIGEST"', text)
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
