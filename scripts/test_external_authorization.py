#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import external_authorization as verifier  # noqa: I001


CANDIDATE_REPOSITORY = "taipei49314/tomorrowci-lab"
EXTERNAL_REPOSITORY = "independent-auditor/tomorrowci-qualification"
CANDIDATE_SHA = "a" * 40
EXTERNAL_SHA = "b" * 40
RUN_ID = 31452436560
EXTERNAL_RUN_ID = 900000001
AUTHORIZATION_ID = "d" * 64
PRINCIPAL = "auditor@example.invalid"
VERSION = "0.2.0-alpha.1"
IMAGE_DIGEST = "sha256:" + "3" * 64
NOW = datetime(2026, 8, 11, 2, 0, 0, tzinfo=timezone.utc)


def canonical(value: object) -> bytes:
    return verifier._canonical_bytes(value)


def pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class ExternalAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.fail("ssh-keygen is required: verifier must fail closed without it")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "fixture-only-auditor-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
            capture_output=True,
        )
        public = self.key.with_suffix(".pub").read_text(encoding="ascii").split()
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(
            f"{PRINCIPAL} {public[0]} {public[1]} fixture-only\n",
            encoding="ascii",
            newline="\n",
        )
        self.manifest = self.root / "candidate-manifest.json"
        self.provenance = self.root / "image-provenance.json"
        self.evidence = self.root / "external-evidence.json"
        self.authorization = self.root / "external-authorization.json"
        self.policy_path = self.root / "external-policy.json"

        manifest_value = {
            "build": {
                "reproducible_builds": 2,
                "rust_toolchain": "1.88.0",
            },
            "kind": "tomorrowci.release-candidate.v1",
            "payload": [
                {
                    "name": "fixture.tar.gz",
                    "sha256": "sha256:" + "1" * 64,
                    "size": 123,
                }
            ],
            "promotion": {
                "authorization_source": None,
                "authorized": False,
                "instruction": "Bind detached external authorization to this manifest's SHA-256 digest.",
            },
            "schema_version": 1,
            "source": {
                "commit": CANDIDATE_SHA,
                "dirty": False,
                "ref": "refs/heads/master",
                "repository": CANDIDATE_REPOSITORY,
            },
            "status": "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED",
            "version": VERSION,
            "workflow": {
                "name": "release-candidate",
                "run_attempt": 1,
                "run_id": RUN_ID,
                "run_url": f"https://github.com/{CANDIDATE_REPOSITORY}/actions/runs/{RUN_ID}/attempts/1",
                "workflow_ref": f"{CANDIDATE_REPOSITORY}/.github/workflows/candidate.yml@refs/heads/master",
            },
        }
        self.manifest.write_bytes(pretty(manifest_value))
        provenance_value = {
            "build": {},
            "kind": "tomorrowci.oci-candidate-provenance.v1",
            "oci": {
                "manifest": {
                    "digest": IMAGE_DIGEST,
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
                "commit": CANDIDATE_SHA,
                "repository": CANDIDATE_REPOSITORY,
                "url": f"https://github.com/{CANDIDATE_REPOSITORY}",
            },
            "status": "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED",
            "version": VERSION,
            "workflow": {
                "run_attempt": 1,
                "run_id": RUN_ID,
                "run_url": f"https://github.com/{CANDIDATE_REPOSITORY}/actions/runs/{RUN_ID}/attempts/1",
            },
        }
        self.provenance.write_bytes(pretty(provenance_value))
        candidate = {
            "commit": CANDIDATE_SHA,
            "manifest_sha256": digest(self.manifest),
            "oci_manifest_digest": IMAGE_DIGEST,
            "oci_provenance_sha256": digest(self.provenance),
            "ref": "refs/heads/master",
            "repository": CANDIDATE_REPOSITORY,
            "run_attempt": 1,
            "run_id": RUN_ID,
            "version": VERSION,
        }
        external_policy = {
            "artifact_name": "external-qualification-evidence",
            "auditor_principal": PRINCIPAL,
            "authorization_id": AUTHORIZATION_ID,
            "commit": EXTERNAL_SHA,
            "engine_name": "podman",
            "repository": EXTERNAL_REPOSITORY,
            "run_attempt": 2,
            "run_id": EXTERNAL_RUN_ID,
            "workflow_path": ".github/workflows/qualify.yml",
        }
        self.policy = {
            "candidate": candidate,
            "external": external_policy,
            "kind": verifier.POLICY_KIND,
            "schema_version": 1,
            "trust": {
                "allowed_signers_sha256": digest(self.allowed),
                "namespace": verifier.NAMESPACE,
            },
            "validity": {
                "not_after": "2026-08-13T00:00:00Z",
                "not_before": "2026-08-11T00:00:00Z",
            },
        }
        external_auth = dict(external_policy)
        external_auth.update(
            {
                "run_url": f"https://github.com/{EXTERNAL_REPOSITORY}/actions/runs/{EXTERNAL_RUN_ID}/attempts/2",
                "workflow_ref": f"{EXTERNAL_REPOSITORY}/.github/workflows/qualify.yml@{EXTERNAL_SHA}",
            }
        )
        self.evidence_value = {
            "artifact_name": "external-qualification-evidence",
            "candidate": {"image_digest": IMAGE_DIGEST},
            "engine": {"name": "podman", "version": "5.4.2"},
            "external": {
                "commit": EXTERNAL_SHA,
                "conclusion": "success",
                "repository": EXTERNAL_REPOSITORY,
                "run_attempt": 2,
                "run_id": EXTERNAL_RUN_ID,
                "run_url": f"https://github.com/{EXTERNAL_REPOSITORY}/actions/runs/{EXTERNAL_RUN_ID}/attempts/2",
                "workflow_path": ".github/workflows/qualify.yml",
                "workflow_ref": f"{EXTERNAL_REPOSITORY}/.github/workflows/qualify.yml@{EXTERNAL_SHA}",
            },
            "kind": verifier.EVIDENCE_KIND,
            "qualification": {
                "checks": {name: "PASS" for name in verifier.QUALIFICATION_CHECKS},
                "result": "PASS",
            },
            "schema_version": 1,
            "status": "PASS",
        }
        self.write_evidence()
        self.auth = {
            "auditor": {"principal": PRINCIPAL},
            "candidate": candidate,
            "decision": verifier.DECISION,
            "evidence": {
                "engine": {"name": "podman", "version": "5.4.2"},
                "image_digest": IMAGE_DIGEST,
                "name": "external-qualification-evidence",
                "sha256": digest(self.evidence),
                "size": self.evidence.stat().st_size,
            },
            "expires_at": "2026-08-12T00:00:00Z",
            "external": external_auth,
            "issued_at": "2026-08-11T01:00:00Z",
            "kind": verifier.AUTH_KIND,
            "schema_version": 1,
        }
        self.write_and_sign()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_evidence(self) -> None:
        self.evidence.write_bytes(canonical(self.evidence_value))

    def bind_evidence_and_sign(self) -> None:
        self.auth["evidence"]["sha256"] = digest(self.evidence)
        self.auth["evidence"]["size"] = self.evidence.stat().st_size
        self.write_and_sign()

    def write_policy(self) -> None:
        self.policy_path.write_bytes(canonical(self.policy))

    def write_and_sign(self) -> None:
        self.write_policy()
        policy_signature = Path(str(self.policy_path) + ".sig")
        if policy_signature.exists():
            policy_signature.unlink()
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(self.key),
                "-n",
                verifier.NAMESPACE,
                str(self.policy_path),
            ],
            check=True,
            capture_output=True,
        )
        self.authorization.write_bytes(canonical(self.auth))
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
                verifier.NAMESPACE,
                str(self.authorization),
            ],
            check=True,
            capture_output=True,
        )

    def arguments(self) -> dict:
        return {
            "authorization": self.authorization,
            "signature": Path(str(self.authorization) + ".sig"),
            "policy": self.policy_path,
            "policy_signature": Path(str(self.policy_path) + ".sig"),
            "allowed_signers": self.allowed,
            "candidate_manifest": self.manifest,
            "oci_provenance": self.provenance,
            "evidence": self.evidence,
        }

    def verify(self, **overrides: object) -> verifier.VerifiedAuthorization:
        arguments = self.arguments()
        arguments["now"] = NOW
        arguments.update(overrides)
        return verifier.verify_authorization(**arguments)

    def test_accepts_exact_preregistered_signed_authorization(self) -> None:
        verified = self.verify()
        self.assertEqual(verified.authorization_id, AUTHORIZATION_ID)
        self.assertEqual(verified.authorization_sha256, digest(self.authorization))
        self.assertEqual(verified.receipt()["status"], verifier.RECEIPT_STATUS)
        self.assertNotIn("consumed", verified.receipt())

    def test_cli_emits_canonical_digest_receipt(self) -> None:
        verified = self.verify()
        output = io.BytesIO()
        cli: list[str] = []
        for name, value in self.arguments().items():
            cli.extend(("--" + name.replace("_", "-"), str(value)))
        with (
            patch("external_authorization.verify_authorization", return_value=verified),
            patch.object(sys, "stdout", SimpleNamespace(buffer=output)),
        ):
            self.assertEqual(verifier.main(cli), 0)
        self.assertEqual(output.getvalue(), canonical(verified.receipt()))
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["authorization"]["sha256"], digest(self.authorization))

    def test_rejects_replaced_externally_signed_policy(self) -> None:
        self.policy_path.write_bytes(self.policy_path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "canonical JSON|signature verification failed"):
            self.verify()

    def test_rejects_duplicate_noncanonical_and_unknown_json(self) -> None:
        original = copy.deepcopy(self.auth)
        with self.subTest("duplicate"):
            self.authorization.write_text(
                '{"kind":"first","kind":"second"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                self.verify()
        with self.subTest("noncanonical"):
            self.authorization.write_text(
                json.dumps(original, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "not canonical JSON"):
                self.verify()
        with self.subTest("unknown"):
            self.auth = copy.deepcopy(original)
            self.auth["unexpected"] = True
            self.write_and_sign()
            with self.assertRaisesRegex(ValueError, "unexpected schema"):
                self.verify()

    def test_rejects_wrong_sha_run_attempt_and_moving_workflow_ref(self) -> None:
        mutations = (
            lambda: self.auth["external"].update(commit="c" * 40),
            lambda: self.auth["external"].update(run_id=EXTERNAL_RUN_ID + 1),
            lambda: self.auth["external"].update(run_attempt=3),
            lambda: self.auth["external"].update(
                workflow_ref=(
                    f"{EXTERNAL_REPOSITORY}/.github/workflows/qualify.yml@refs/heads/main"
                )
            ),
        )
        original = copy.deepcopy(self.auth)
        for mutate in mutations:
            self.auth = copy.deepcopy(original)
            mutate()
            self.write_and_sign()
            with self.assertRaises(ValueError):
                self.verify()

    def test_rejects_same_owner_and_same_repository_case_insensitively(self) -> None:
        for repository in (
            CANDIDATE_REPOSITORY.upper(),
            "TAIPEI49314/external-fixture",
        ):
            self.auth["external"]["repository"] = repository
            self.auth["external"]["workflow_ref"] = (
                f"{repository}/.github/workflows/qualify.yml@{EXTERNAL_SHA}"
            )
            self.auth["external"]["run_url"] = (
                f"https://github.com/{repository}/actions/runs/{EXTERNAL_RUN_ID}/attempts/2"
            )
            self.policy["external"]["repository"] = repository
            self.write_and_sign()
            with self.assertRaisesRegex(ValueError, "independent|must differ"):
                self.verify()

    def test_rejects_expiry_and_cli_has_no_caller_time_or_ledger(self) -> None:
        with self.assertRaisesRegex(ValueError, "not currently valid"):
            self.verify(now=datetime(2026, 8, 12, tzinfo=timezone.utc))
        cli = []
        for name, value in self.arguments().items():
            cli.extend(("--" + name.replace("_", "-"), str(value)))
        for forbidden in ("--verification-time", "--consumed-authorizations"):
            with (
                self.subTest(forbidden),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                verifier.main([*cli, forbidden, "caller-controlled"])

    def test_rejects_arbitrary_or_semantically_false_evidence(self) -> None:
        self.evidence.write_bytes(b"arbitrary independently signed bytes\n")
        self.bind_evidence_and_sign()
        with self.assertRaisesRegex(ValueError, "not strict JSON|root|canonical"):
            self.verify()

        mutations = (
            lambda: self.evidence_value["external"].update(conclusion="failure"),
            lambda: self.evidence_value["external"].update(run_id=1),
            lambda: self.evidence_value["qualification"]["checks"].update(
                live_runtime="FAIL"
            ),
            lambda: self.evidence_value["candidate"].update(
                image_digest="sha256:" + "4" * 64
            ),
        )
        for mutate in mutations:
            self.setUpEvidenceBaseline()
            mutate()
            self.write_evidence()
            self.bind_evidence_and_sign()
            with self.assertRaises(ValueError):
                self.verify()

    def setUpEvidenceBaseline(self) -> None:
        self.evidence_value["candidate"]["image_digest"] = IMAGE_DIGEST
        self.evidence_value["external"].update(
            conclusion="success",
            run_id=EXTERNAL_RUN_ID,
        )
        self.evidence_value["qualification"]["checks"] = {
            name: "PASS" for name in verifier.QUALIFICATION_CHECKS
        }

    def test_rejects_changed_candidate_provenance_and_evidence_bytes(self) -> None:
        for path, message in (
            (self.manifest, "manifest digest"),
            (self.provenance, "provenance digest"),
            (self.evidence, "evidence bytes"),
        ):
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.assertRaisesRegex(ValueError, message):
                self.verify()
            path.write_bytes(original)

    def test_rejects_untrusted_key_bad_signature_and_missing_binary(self) -> None:
        signature = Path(str(self.authorization) + ".sig")
        raw = bytearray(signature.read_bytes())
        raw[-10] ^= 1
        signature.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self.verify()
        self.write_and_sign()
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.verify(ssh_keygen="definitely-not-a-real-ssh-keygen")
        self.allowed.write_bytes(self.allowed.read_bytes() + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "trust root digest mismatch"):
            self.verify()

    def test_policy_snapshot_prevents_digest_then_parse_swap(self) -> None:
        good_policy = self.policy_path.read_bytes()
        self.policy["external"]["authorization_id"] = "e" * 64
        self.auth["external"]["authorization_id"] = "e" * 64
        self.write_and_sign()
        bad_policy = self.policy_path.read_bytes()
        self.policy_path.write_bytes(good_policy)
        real_snapshot = verifier._snapshot

        def snapshot_then_swap(path: Path, label: str):
            result = real_snapshot(path, label)
            if label == "authorization policy":
                self.policy_path.write_bytes(bad_policy)
            return result

        with (
            patch("external_authorization._snapshot", side_effect=snapshot_then_swap),
            self.assertRaisesRegex(ValueError, "external run"),
        ):
            self.verify()

    def test_authorization_snapshot_prevents_parse_then_signature_swap(self) -> None:
        signed_bytes = self.authorization.read_bytes()
        self.evidence_value["engine"]["version"] = "5.4.3"
        self.write_evidence()
        self.auth["evidence"]["engine"]["version"] = "5.4.3"
        self.auth["evidence"]["sha256"] = digest(self.evidence)
        self.auth["evidence"]["size"] = self.evidence.stat().st_size
        self.authorization.write_bytes(canonical(self.auth))
        real_snapshot = verifier._snapshot

        def snapshot_then_swap(path: Path, label: str):
            result = real_snapshot(path, label)
            if label == "external authorization":
                self.authorization.write_bytes(signed_bytes)
            return result

        with (
            patch("external_authorization._snapshot", side_effect=snapshot_then_swap),
            self.assertRaisesRegex(ValueError, "signature verification failed"),
        ):
            self.verify()

    def test_allowed_signers_snapshot_prevents_trust_root_swap(self) -> None:
        attacker = self.root / "attacker-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(attacker)],
            check=True,
            capture_output=True,
        )
        signature = Path(str(self.authorization) + ".sig")
        signature.unlink()
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(attacker),
                "-n",
                verifier.NAMESPACE,
                str(self.authorization),
            ],
            check=True,
            capture_output=True,
        )
        public = attacker.with_suffix(".pub").read_text(encoding="ascii").split()
        attacker_root = f"{PRINCIPAL} {public[0]} {public[1]} attacker\n".encode()
        real_snapshot = verifier._snapshot

        def snapshot_then_swap(path: Path, label: str):
            result = real_snapshot(path, label)
            if label == "allowed signers trust root":
                self.allowed.write_bytes(attacker_root)
            return result

        with (
            patch("external_authorization._snapshot", side_effect=snapshot_then_swap),
            self.assertRaisesRegex(ValueError, "signature verification failed"),
        ):
            self.verify()


if __name__ == "__main__":
    unittest.main()
