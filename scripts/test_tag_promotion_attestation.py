#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import candidate_manifest
import external_authorization
import tag_promotion_attestation as promotion
import test_oci_candidate as oci_fixture


class TagPromotionAttestationTests(unittest.TestCase):
    VERSION = "1.2.3-alpha.1"
    REPOSITORY = "candidate-owner/tomorrowci-lab"
    EXTERNAL_REPOSITORY = "independent-owner/tomorrowci-qualification"
    PRINCIPAL = "auditor@example.invalid"
    EXTERNAL_SHA = "b" * 40
    EXTERNAL_RUN_ID = 900000001
    AUTH_ID = "d" * 64
    NOW = datetime(2026, 8, 11, 2, tzinfo=timezone.utc)

    def setUp(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.fail("ssh-keygen is required for the end-to-end authorization gate")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self._git("init", "-q")
        self._git("config", "user.name", "Fixture")
        self._git("config", "user.email", "fixture@example.invalid")
        (self.repo / "tracked.txt").write_text("candidate\n", encoding="utf-8")
        self._git("add", "tracked.txt")
        self._git("commit", "-q", "-m", "candidate")
        self.commit = self._git("rev-parse", "HEAD")
        self.tag_name = f"v{self.VERSION}"
        self._git("tag", "-a", self.tag_name, "-m", "annotated fixture")

        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.payload_names = [
            "Containerfile",
            "build-metadata.json",
            "image-provenance.json",
            "tomorrowci-oci-linux-amd64.tar",
            "tomorrowci-v1.2.3-alpha.1-x86_64-unknown-linux-gnu.tar.gz",
        ]
        for position, name in enumerate(self.payload_names):
            (self.dist / name).write_bytes(f"fixture-{position}\n".encode("ascii"))
        self.oci_manifest = "sha256:" + "a" * 64
        self.run_id = 123
        self.run_attempt = 1
        self.provenance = {
            "build": {},
            "kind": "tomorrowci.oci-candidate-provenance.v1",
            "oci": {
                "manifest": {
                    "digest": self.oci_manifest,
                    "media_type": "application/vnd.oci.image.manifest.v1+json",
                    "size": 123,
                }
            },
            "promotion": {
                "authorization_source": None,
                "authorized": False,
                "instruction": "Bind independent exact-SHA authorization before publication.",
            },
            "schema_version": 1,
            "source": {
                "commit": self.commit,
                "repository": self.REPOSITORY,
                "url": f"https://github.com/{self.REPOSITORY}",
            },
            "status": "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED",
            "version": self.VERSION,
            "workflow": {
                "run_attempt": self.run_attempt,
                "run_id": self.run_id,
                "run_url": f"https://github.com/{self.REPOSITORY}/actions/runs/{self.run_id}/attempts/{self.run_attempt}",
            },
        }
        (self.dist / "image-provenance.json").write_bytes(
            promotion.canonical_bytes(self.provenance)
        )
        self.candidate = {
            "build": {"reproducible_builds": 2, "rust_toolchain": "1.88.0"},
            "kind": "tomorrowci.release-candidate.v1",
            "payload": [
                {
                    "name": name,
                    "sha256": self._file_digest(self.dist / name),
                    "size": (self.dist / name).stat().st_size,
                }
                for name in self.payload_names
            ],
            "promotion": {
                "authorization_source": None,
                "authorized": False,
                "instruction": "Bind detached external authorization to this manifest's SHA-256 digest.",
            },
            "schema_version": 1,
            "source": {
                "commit": self.commit,
                "dirty": False,
                "ref": "refs/heads/master",
                "repository": self.REPOSITORY,
            },
            "status": "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED",
            "version": self.VERSION,
            "workflow": {
                "name": "release-candidate",
                "run_attempt": self.run_attempt,
                "run_id": self.run_id,
                "run_url": f"https://github.com/{self.REPOSITORY}/actions/runs/{self.run_id}/attempts/{self.run_attempt}",
                "workflow_ref": f"{self.REPOSITORY}/.github/workflows/candidate.yml@refs/heads/master",
            },
        }
        (self.dist / promotion.MANIFEST_NAME).write_bytes(
            promotion.canonical_bytes(self.candidate)
        )
        (self.dist / promotion.CHECKSUMS_NAME).write_text(
            "fixture checksums\n", encoding="ascii", newline="\n"
        )
        self.attestation = self.root / "tag-promotion-attestation.json"

        self.key = self.root / "fixture-auditor-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
            capture_output=True,
        )
        public = self.key.with_suffix(".pub").read_text(encoding="ascii").split()
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(
            f"{self.PRINCIPAL} {public[0]} {public[1]} fixture\n",
            encoding="ascii",
            newline="\n",
        )
        self.evidence = self.root / "external-evidence.json"
        self.evidence_value = {
            "artifact_name": "external-qualification-evidence",
            "candidate": {"image_digest": self.oci_manifest},
            "engine": {"name": "podman", "version": "5.4.2"},
            "external": {
                "commit": self.EXTERNAL_SHA,
                "conclusion": "success",
                "repository": self.EXTERNAL_REPOSITORY,
                "run_attempt": 2,
                "run_id": self.EXTERNAL_RUN_ID,
                "run_url": f"https://github.com/{self.EXTERNAL_REPOSITORY}/actions/runs/{self.EXTERNAL_RUN_ID}/attempts/2",
                "workflow_path": ".github/workflows/qualify.yml",
                "workflow_ref": f"{self.EXTERNAL_REPOSITORY}/.github/workflows/qualify.yml@{self.EXTERNAL_SHA}",
            },
            "kind": external_authorization.EVIDENCE_KIND,
            "qualification": {
                "checks": {
                    name: "PASS" for name in external_authorization.QUALIFICATION_CHECKS
                },
                "result": "PASS",
            },
            "schema_version": 1,
            "status": "PASS",
        }
        self.evidence.write_bytes(
            external_authorization._canonical_bytes(self.evidence_value)
        )
        self.policy_path = self.root / "external-policy.json"
        self.authorization = self.root / "external-authorization.json"
        candidate_binding = {
            "commit": self.commit,
            "manifest_sha256": self._file_digest(self.dist / promotion.MANIFEST_NAME),
            "oci_manifest_digest": self.oci_manifest,
            "oci_provenance_sha256": self._file_digest(
                self.dist / "image-provenance.json"
            ),
            "ref": "refs/heads/master",
            "repository": self.REPOSITORY,
            "run_attempt": self.run_attempt,
            "run_id": self.run_id,
            "version": self.VERSION,
        }
        external_binding = {
            "artifact_name": "external-qualification-evidence",
            "auditor_principal": self.PRINCIPAL,
            "authorization_id": self.AUTH_ID,
            "commit": self.EXTERNAL_SHA,
            "engine_name": "podman",
            "repository": self.EXTERNAL_REPOSITORY,
            "run_attempt": 2,
            "run_id": self.EXTERNAL_RUN_ID,
            "workflow_path": ".github/workflows/qualify.yml",
        }
        self.policy = {
            "candidate": candidate_binding,
            "external": external_binding,
            "kind": external_authorization.POLICY_KIND,
            "schema_version": 1,
            "trust": {
                "allowed_signers_sha256": self._file_digest(self.allowed),
                "namespace": external_authorization.NAMESPACE,
            },
            "validity": {
                "not_after": "2026-08-13T00:00:00Z",
                "not_before": "2026-08-11T00:00:00Z",
            },
        }
        external_auth = dict(external_binding)
        external_auth.update(
            {
                "run_url": f"https://github.com/{self.EXTERNAL_REPOSITORY}/actions/runs/{self.EXTERNAL_RUN_ID}/attempts/2",
                "workflow_ref": f"{self.EXTERNAL_REPOSITORY}/.github/workflows/qualify.yml@{self.EXTERNAL_SHA}",
            }
        )
        self.auth = {
            "auditor": {"principal": self.PRINCIPAL},
            "candidate": candidate_binding,
            "decision": external_authorization.DECISION,
            "evidence": {
                "engine": {"name": "podman", "version": "5.4.2"},
                "image_digest": self.oci_manifest,
                "name": "external-qualification-evidence",
                "sha256": self._file_digest(self.evidence),
                "size": self.evidence.stat().st_size,
            },
            "expires_at": "2026-08-12T00:00:00Z",
            "external": external_auth,
            "issued_at": "2026-08-11T01:00:00Z",
            "kind": external_authorization.AUTH_KIND,
            "schema_version": 1,
        }
        self._write_and_sign_authorization()
        self.verified = self._verify_external()

        self.candidate_patch = patch(
            "tag_promotion_attestation.candidate_manifest.verify_candidate",
            side_effect=lambda **_: copy.deepcopy(self.candidate),
        )
        self.oci_patch = patch(
            "tag_promotion_attestation.oci_candidate.verify_candidate",
            side_effect=lambda **_: copy.deepcopy(self.provenance),
        )
        self.candidate_patch.start()
        self.oci_patch.start()

    def tearDown(self) -> None:
        self.oci_patch.stop()
        self.candidate_patch.stop()
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    @staticmethod
    def _file_digest(path: Path) -> str:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_and_sign_authorization(self) -> None:
        self.policy_path.write_bytes(
            external_authorization._canonical_bytes(self.policy)
        )
        self.authorization.write_bytes(
            external_authorization._canonical_bytes(self.auth)
        )
        signature = Path(str(self.authorization) + ".sig")
        if signature.exists():
            signature.unlink()
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(self.key),
                "-n",
                external_authorization.NAMESPACE,
                str(self.authorization),
            ],
            check=True,
            capture_output=True,
        )

    def _verify_external(self) -> external_authorization.VerifiedAuthorization:
        return external_authorization.verify_authorization(
            authorization=self.authorization,
            signature=Path(str(self.authorization) + ".sig"),
            policy=self.policy_path,
            expected_policy_sha256=self._file_digest(self.policy_path),
            allowed_signers=self.allowed,
            candidate_manifest=self.dist / promotion.MANIFEST_NAME,
            oci_provenance=self.dist / "image-provenance.json",
            evidence=self.evidence,
            now=self.NOW,
        )

    def _build(self) -> dict:
        return promotion.build_qualification_index(
            git_repo=self.repo,
            candidate_dir=self.dist,
            verified_authorization=self.verified,
        )

    def _write(self, document: dict) -> None:
        self.attestation.write_bytes(promotion.canonical_bytes(document))

    def _verify(self) -> dict:
        return promotion.verify_qualification_index(
            attestation=self.attestation,
            git_repo=self.repo,
            candidate_dir=self.dist,
            verified_authorization=self.verified,
        )

    def test_accepts_exact_annotated_tag_inventory_and_real_ssh_authorization(
        self,
    ) -> None:
        document = self._build()
        self._write(document)
        verified = self._verify()
        self.assertEqual(verified["tag"]["peeled_commit"], self.commit)
        self.assertEqual(verified["oci"]["manifest_sha256"], self.oci_manifest)
        self.assertEqual(verified["status"], promotion.STATUS)
        self.assertEqual(
            verified["external_authorization"]["authorization"]["sha256"],
            self._file_digest(self.authorization),
        )

    def test_rejects_lightweight_tag(self) -> None:
        document = self._build()
        self._write(document)
        self._git("tag", "-d", self.tag_name)
        self._git("tag", self.tag_name, self.commit)
        with self.assertRaisesRegex(ValueError, "lightweight tag"):
            self._verify()

    def test_rejects_wrong_tag_version_commit_and_candidate(self) -> None:
        original = self._build()
        mutations = (
            ("tag", "name", "v9.9.9"),
            ("tag", "object_sha", "d" * 40),
            ("candidate", "version", "9.9.9"),
            ("candidate", "source_sha", "f" * 40),
            ("tag", "peeled_commit", "e" * 40),
        )
        for section, field, value in mutations:
            document = copy.deepcopy(original)
            document[section][field] = value
            self._write(document)
            with self.assertRaisesRegex(ValueError, "does not match"):
                self._verify()

    def test_rejects_rebuilt_asset_and_inventory_drift(self) -> None:
        self._write(self._build())
        (self.dist / self.payload_names[-1]).write_bytes(b"rebuilt different bytes\n")
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._verify()
        (self.dist / "unexpected.bin").write_bytes(b"extra\n")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            self._verify()

    def test_rejects_naked_digest_and_bad_external_signature(self) -> None:
        with self.assertRaisesRegex(ValueError, "VerifiedAuthorization"):
            promotion.build_qualification_index(
                git_repo=self.repo,
                candidate_dir=self.dist,
                verified_authorization="sha256:" + "0" * 64,  # type: ignore[arg-type]
            )
        signature = Path(str(self.authorization) + ".sig")
        raw = bytearray(signature.read_bytes())
        raw[-10] ^= 1
        signature.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self._verify_external()

    def test_authorization_capability_is_an_immutable_snapshot(self) -> None:
        original_identity = self.verified.stable_identity()
        self.authorization.write_bytes(b"later self assertion\n")
        document = self._build()
        self.assertEqual(document["external_authorization"], original_identity)
        self.assertNotIn("verified_at", document["external_authorization"])

    def test_rejects_tag_ref_swap_after_object_capture(self) -> None:
        (self.repo / "other.txt").write_text("other\n", encoding="utf-8")
        self._git("add", "other.txt")
        self._git("commit", "-q", "-m", "other")
        self._git("tag", "-a", "alternate", "-m", "alternate")
        alternate = self._git("rev-parse", "refs/tags/alternate")
        real_git = promotion._git
        swapped = False

        def capture_then_swap(repo: Path, *arguments: str) -> str:
            nonlocal swapped
            result = real_git(repo, *arguments)
            if (
                arguments
                == (
                    "show-ref",
                    "--verify",
                    "--hash",
                    f"refs/tags/{self.tag_name}",
                )
                and not swapped
            ):
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.repo),
                        "update-ref",
                        f"refs/tags/{self.tag_name}",
                        alternate,
                    ],
                    check=True,
                    capture_output=True,
                )
                swapped = True
            return result

        with (
            patch("tag_promotion_attestation._git", side_effect=capture_then_swap),
            self.assertRaisesRegex(ValueError, "ref changed"),
        ):
            self._build()

    def test_rejects_tag_object_with_alias_internal_name(self) -> None:
        self._git("tag", "-a", "alias-name", "-m", "alias")
        alias_object = self._git("rev-parse", "refs/tags/alias-name")
        self._git(
            "update-ref",
            f"refs/tags/{self.tag_name}",
            alias_object,
        )
        with self.assertRaisesRegex(ValueError, "internal name"):
            self._build()

    def test_rejects_symbolic_tag_ref_alias(self) -> None:
        self._git("tag", "-a", "direct-target", "-m", "direct")
        self._git("update-ref", "-d", f"refs/tags/{self.tag_name}")
        self._git(
            "symbolic-ref",
            f"refs/tags/{self.tag_name}",
            "refs/tags/direct-target",
        )
        with self.assertRaisesRegex(ValueError, "symbolic alias"):
            self._build()

    def test_rejects_direct_to_symbolic_same_object_race(self) -> None:
        object_sha = self._git("rev-parse", f"refs/tags/{self.tag_name}")
        same_target = "refs/tags/same-object-target"
        self._git("update-ref", same_target, object_sha)
        real_git = promotion._git
        swapped = False

        def capture_then_make_symbolic(repo: Path, *arguments: str) -> str:
            nonlocal swapped
            result = real_git(repo, *arguments)
            if (
                arguments
                == (
                    "show-ref",
                    "--verify",
                    "--hash",
                    f"refs/tags/{self.tag_name}",
                )
                and not swapped
            ):
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.repo),
                        "update-ref",
                        "-d",
                        f"refs/tags/{self.tag_name}",
                    ],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.repo),
                        "symbolic-ref",
                        f"refs/tags/{self.tag_name}",
                        same_target,
                    ],
                    check=True,
                    capture_output=True,
                )
                swapped = True
            return result

        with (
            patch(
                "tag_promotion_attestation._git",
                side_effect=capture_then_make_symbolic,
            ),
            self.assertRaisesRegex(ValueError, "became a symbolic alias"),
        ):
            self._build()

    def test_replace_ref_cannot_substitute_tag_object_content(self) -> None:
        canonical = self._git("rev-parse", f"refs/tags/{self.tag_name}")
        self._git("tag", "-a", "replace-hidden-alias", "-m", "hidden alias")
        hidden_alias = self._git("rev-parse", "refs/tags/replace-hidden-alias")
        self._git("update-ref", f"refs/tags/{self.tag_name}", hidden_alias)
        self._git("replace", hidden_alias, canonical)
        with self.assertRaisesRegex(ValueError, "internal name"):
            self._build()

    def test_rejects_transient_same_target_different_tagger_object_swap(self) -> None:
        object_sha = self._git("rev-parse", f"refs/tags/{self.tag_name}")
        raw = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-C",
                str(self.repo),
                "cat-file",
                "tag",
                object_sha,
            ],
            check=True,
            capture_output=True,
        ).stdout
        swapped_raw = raw.replace(b"tagger Fixture ", b"tagger Other-Fixture ", 1)
        self.assertNotEqual(swapped_raw, raw)
        swapped_sha = (
            subprocess.run(
                ["git", "--no-replace-objects", "-C", str(self.repo), "mktag"],
                input=swapped_raw,
                check=True,
                capture_output=True,
            )
            .stdout.decode("ascii")
            .strip()
        )
        self.assertNotEqual(swapped_sha, object_sha)
        stored_swapped_raw = subprocess.run(
            [
                "git",
                "--no-replace-objects",
                "-C",
                str(self.repo),
                "cat-file",
                "tag",
                swapped_sha,
            ],
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(stored_swapped_raw, swapped_raw)
        real_raw = promotion._git_raw

        def substitute_raw(repo: Path, *arguments: str) -> bytes:
            if arguments == ("cat-file", "tag", object_sha):
                return stored_swapped_raw
            return real_raw(repo, *arguments)

        with (
            patch("tag_promotion_attestation._git_raw", side_effect=substitute_raw),
            self.assertRaisesRegex(ValueError, "captured object SHA"),
        ):
            self._build()

    def test_rejects_annotated_tag_that_targets_another_tag(self) -> None:
        self._git("tag", "-a", "nested-alias", "-m", "nested", self.tag_name)
        nested_object = self._git("rev-parse", "refs/tags/nested-alias")
        raw = subprocess.run(
            ["git", "-C", str(self.repo), "cat-file", "tag", nested_object],
            check=True,
            capture_output=True,
        ).stdout
        raw = raw.replace(b"tag nested-alias\n", f"tag {self.tag_name}\n".encode(), 1)
        canonical_nested = (
            subprocess.run(
                ["git", "-C", str(self.repo), "mktag"],
                input=raw,
                check=True,
                capture_output=True,
                text=False,
            )
            .stdout.decode("ascii")
            .strip()
        )
        self._git(
            "update-ref",
            f"refs/tags/{self.tag_name}",
            canonical_nested,
        )
        with self.assertRaisesRegex(ValueError, "target a commit directly"):
            self._build()

    def test_rejects_wrong_oci_and_external_receipt_fields(self) -> None:
        original = self._build()
        for section, field in (
            ("oci", "manifest_sha256"),
            ("oci", "provenance_sha256"),
        ):
            document = copy.deepcopy(original)
            document[section][field] = "sha256:" + "b" * 64
            self._write(document)
            with self.assertRaisesRegex(ValueError, "does not match"):
                self._verify()
        document = copy.deepcopy(original)
        document["external_authorization"]["status"] = "SELF_AUTHORIZED"
        self._write(document)
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._verify()

    def test_rejects_duplicate_noncanonical_and_strict_type_json(self) -> None:
        document = self._build()
        canonical = promotion.canonical_bytes(document)
        duplicate = canonical.replace(
            b'{\n  "candidate":', b'{\n  "status": "duplicate",\n  "candidate":', 1
        )
        self.attestation.write_bytes(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self._verify()

        self.attestation.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not canonical JSON"):
            self._verify()

        document["release_assets"][0]["size"] = True
        self._write(document)
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._verify()

    def test_rejects_noncanonical_asset_path_and_digest(self) -> None:
        original = self._build()
        document = copy.deepcopy(original)
        document["release_assets"][0]["name"] = "../asset"
        self._write(document)
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._verify()
        document = copy.deepcopy(original)
        document["candidate"]["manifest_sha256"] = "sha256:" + "A" * 64
        self._write(document)
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._verify()


class FullPromotionEndToEndTests(unittest.TestCase):
    """Exercise real candidate, OCI, SSH authorization, tag, and later replay."""

    VERSION = "0.2.0-alpha.1"
    REPOSITORY = "candidate-owner/full-tomorrowci-lab"
    EXTERNAL_REPOSITORY = "independent-owner/full-qualification"
    PRINCIPAL = "full-auditor@example.invalid"
    EXTERNAL_SHA = "c" * 40
    RUN_ID = 456
    RUN_ATTEMPT = 2
    EXTERNAL_RUN_ID = 900000002
    AUTH_ID = "e" * 64
    FIRST_NOW = datetime(2026, 8, 11, 2, tzinfo=timezone.utc)
    LATER_NOW = datetime(2026, 8, 11, 3, tzinfo=timezone.utc)

    def setUp(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.fail("ssh-keygen is required for the full promotion fixture")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self._git("init", "-q")
        self._git("config", "user.name", "Full Fixture")
        self._git("config", "user.email", "full-fixture@example.invalid")
        (self.repo / "tracked.txt").write_text("full candidate\n", encoding="utf-8")
        self._git("add", "tracked.txt")
        self._git("commit", "-q", "-m", "full candidate")
        self.commit = self._git("rev-parse", "HEAD")
        self.tag_name = f"v{self.VERSION}"
        self._git("tag", "-a", self.tag_name, "-m", "full annotated fixture")

        self.dist = self.root / "dist"
        self.dist.mkdir()
        with patch.multiple(
            oci_fixture,
            SOURCE_SHA=self.commit,
            REPOSITORY=self.REPOSITORY,
            VERSION=self.VERSION,
            RUN_ID=str(self.RUN_ID),
            RUN_ATTEMPT=self.RUN_ATTEMPT,
        ):
            fixture = oci_fixture.OciCandidateTests(
                methodName="test_create_and_verify_canonical_detached_provenance"
            )
            fixture.setUp()
            try:
                self.provenance = fixture._create()
                for source, name in (
                    (fixture.archive, "tomorrowci-oci-linux-amd64.tar"),
                    (fixture.metadata, "build-metadata.json"),
                    (fixture.containerfile, "Containerfile"),
                    (fixture.provenance, "image-provenance.json"),
                ):
                    shutil.copyfile(source, self.dist / name)
            finally:
                fixture.tearDown()

        for name in candidate_manifest.payload_names(self.VERSION):
            path = self.dist / name
            if not path.exists():
                payload = b"{}\n" if name.endswith(".json") else b"full fixture\n"
                path.write_bytes(payload)
        self.candidate = candidate_manifest.create_candidate(
            dist=self.dist,
            version=self.VERSION,
            source_sha=self.commit,
            repository=self.REPOSITORY,
            source_ref="refs/heads/master",
            run_id=str(self.RUN_ID),
            run_attempt=self.RUN_ATTEMPT,
            workflow_ref=(
                f"{self.REPOSITORY}/.github/workflows/candidate.yml@refs/heads/master"
            ),
        )

        self.key = self.root / "full-auditor-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
            capture_output=True,
        )
        public = self.key.with_suffix(".pub").read_text(encoding="ascii").split()
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(
            f"{self.PRINCIPAL} {public[0]} {public[1]} full-fixture\n",
            encoding="ascii",
            newline="\n",
        )
        self.evidence = self.root / "external-evidence.json"
        self.evidence_value = {
            "artifact_name": "full-qualification-evidence",
            "candidate": {"image_digest": self.provenance["oci"]["manifest"]["digest"]},
            "engine": {"name": "podman", "version": "5.4.2"},
            "external": {
                "commit": self.EXTERNAL_SHA,
                "conclusion": "success",
                "repository": self.EXTERNAL_REPOSITORY,
                "run_attempt": 1,
                "run_id": self.EXTERNAL_RUN_ID,
                "run_url": f"https://github.com/{self.EXTERNAL_REPOSITORY}/actions/runs/{self.EXTERNAL_RUN_ID}/attempts/1",
                "workflow_path": ".github/workflows/qualify.yml",
                "workflow_ref": f"{self.EXTERNAL_REPOSITORY}/.github/workflows/qualify.yml@{self.EXTERNAL_SHA}",
            },
            "kind": external_authorization.EVIDENCE_KIND,
            "qualification": {
                "checks": {
                    name: "PASS" for name in external_authorization.QUALIFICATION_CHECKS
                },
                "result": "PASS",
            },
            "schema_version": 1,
            "status": "PASS",
        }
        self.evidence.write_bytes(
            external_authorization._canonical_bytes(self.evidence_value)
        )
        self.policy_path = self.root / "external-policy.json"
        self.authorization = self.root / "external-authorization.json"
        candidate_binding = {
            "commit": self.commit,
            "manifest_sha256": self._file_digest(
                self.dist / candidate_manifest.MANIFEST_NAME
            ),
            "oci_manifest_digest": self.provenance["oci"]["manifest"]["digest"],
            "oci_provenance_sha256": self._file_digest(
                self.dist / "image-provenance.json"
            ),
            "ref": "refs/heads/master",
            "repository": self.REPOSITORY,
            "run_attempt": self.RUN_ATTEMPT,
            "run_id": self.RUN_ID,
            "version": self.VERSION,
        }
        external_binding = {
            "artifact_name": "full-qualification-evidence",
            "auditor_principal": self.PRINCIPAL,
            "authorization_id": self.AUTH_ID,
            "commit": self.EXTERNAL_SHA,
            "engine_name": "podman",
            "repository": self.EXTERNAL_REPOSITORY,
            "run_attempt": 1,
            "run_id": self.EXTERNAL_RUN_ID,
            "workflow_path": ".github/workflows/qualify.yml",
        }
        self.policy = {
            "candidate": candidate_binding,
            "external": external_binding,
            "kind": external_authorization.POLICY_KIND,
            "schema_version": 1,
            "trust": {
                "allowed_signers_sha256": self._file_digest(self.allowed),
                "namespace": external_authorization.NAMESPACE,
            },
            "validity": {
                "not_after": "2026-08-13T00:00:00Z",
                "not_before": "2026-08-11T00:00:00Z",
            },
        }
        external_auth = dict(external_binding)
        external_auth.update(
            {
                "run_url": f"https://github.com/{self.EXTERNAL_REPOSITORY}/actions/runs/{self.EXTERNAL_RUN_ID}/attempts/1",
                "workflow_ref": f"{self.EXTERNAL_REPOSITORY}/.github/workflows/qualify.yml@{self.EXTERNAL_SHA}",
            }
        )
        self.auth = {
            "auditor": {"principal": self.PRINCIPAL},
            "candidate": candidate_binding,
            "decision": external_authorization.DECISION,
            "evidence": {
                "engine": {"name": "podman", "version": "5.4.2"},
                "image_digest": self.provenance["oci"]["manifest"]["digest"],
                "name": "full-qualification-evidence",
                "sha256": self._file_digest(self.evidence),
                "size": self.evidence.stat().st_size,
            },
            "expires_at": "2026-08-12T00:00:00Z",
            "external": external_auth,
            "issued_at": "2026-08-11T01:00:00Z",
            "kind": external_authorization.AUTH_KIND,
            "schema_version": 1,
        }
        self.policy_path.write_bytes(
            external_authorization._canonical_bytes(self.policy)
        )
        self.authorization.write_bytes(
            external_authorization._canonical_bytes(self.auth)
        )
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(self.key),
                "-n",
                external_authorization.NAMESPACE,
                str(self.authorization),
            ],
            check=True,
            capture_output=True,
        )
        self.attestation = self.root / "tag-promotion-attestation.json"

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

    @staticmethod
    def _file_digest(path: Path) -> str:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def _verify_external(
        self, now: datetime
    ) -> external_authorization.VerifiedAuthorization:
        return external_authorization.verify_authorization(
            authorization=self.authorization,
            signature=Path(str(self.authorization) + ".sig"),
            policy=self.policy_path,
            expected_policy_sha256=self._file_digest(self.policy_path),
            allowed_signers=self.allowed,
            candidate_manifest=self.dist / candidate_manifest.MANIFEST_NAME,
            oci_provenance=self.dist / "image-provenance.json",
            evidence=self.evidence,
            now=now,
        )

    def test_full_real_e2e_is_time_stable_and_rejects_payload_drift(self) -> None:
        first = self._verify_external(self.FIRST_NOW)
        document = promotion.build_qualification_index(
            git_repo=self.repo,
            candidate_dir=self.dist,
            verified_authorization=first,
        )
        self.assertNotIn("verified_at", document["external_authorization"])
        self.attestation.write_bytes(promotion.canonical_bytes(document))

        later = self._verify_external(self.LATER_NOW)
        self.assertNotEqual(first.verified_at, later.verified_at)
        self.assertEqual(first.stable_identity(), later.stable_identity())
        verified = promotion.verify_qualification_index(
            attestation=self.attestation,
            git_repo=self.repo,
            candidate_dir=self.dist,
            verified_authorization=later,
        )
        self.assertEqual(verified, document)

        payload = self.dist / "claim-to-evidence.md"
        payload.write_bytes(payload.read_bytes() + b"drift\n")
        with self.assertRaisesRegex(ValueError, "payload mismatch"):
            promotion.verify_qualification_index(
                attestation=self.attestation,
                git_repo=self.repo,
                candidate_dir=self.dist,
                verified_authorization=later,
            )


if __name__ == "__main__":
    unittest.main()
