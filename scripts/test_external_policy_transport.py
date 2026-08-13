#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Self

import external_authorization as authorization
import external_policy_transport as transport


def canonical(value: object) -> bytes:
    return authorization._canonical_bytes(value)


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class _Response:
    def __init__(self, url: str, data: bytes) -> None:
        self.status = 200
        self._url = url
        self._data = data
        self.headers = {"Content-Length": str(len(data))}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *unused: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, size: int) -> bytes:
        return self._data[:size]


class _Opener:
    def __init__(self, responses: dict[str, bytes]) -> None:
        self.responses = responses

    def open(self, request: object, timeout: int) -> _Response:
        url = request.full_url  # type: ignore[attr-defined]
        return _Response(url, self.responses[url])


class ExternalPolicyTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.fail("ssh-keygen is required for policy transport verification")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.key = self.root / "auditor"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
            capture_output=True,
        )
        public = self.key.with_suffix(".pub").read_text(encoding="ascii").split()
        self.principal = "auditor@example.invalid"
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(
            f"{self.principal} {public[0]} {public[1]} fixture-only\n",
            encoding="ascii",
            newline="\n",
        )
        self.manifest = self.root / "candidate-manifest.json"
        self.commit = "a" * 40
        self.manifest.write_bytes(
            canonical(
                {
                    "build": {},
                    "kind": "tomorrowci.release-candidate.v1",
                    "payload": [],
                    "promotion": {},
                    "schema_version": 1,
                    "source": {
                        "commit": self.commit,
                        "dirty": False,
                        "ref": "refs/heads/master",
                        "repository": "candidate-owner/candidate",
                    },
                    "status": "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED",
                    "version": "0.2.0-alpha.1",
                    "workflow": {},
                }
            )
        )
        self.manifest_digest = digest(self.manifest.read_bytes())
        self.policy = self.root / "policy.json"
        self.policy.write_bytes(
            canonical(
                {
                    "candidate": {
                        "commit": self.commit,
                        "manifest_sha256": self.manifest_digest,
                        "oci_manifest_digest": "sha256:" + "2" * 64,
                        "oci_provenance_sha256": "sha256:" + "3" * 64,
                        "ref": "refs/heads/master",
                        "repository": "candidate-owner/candidate",
                        "run_attempt": 1,
                        "run_id": 1,
                        "version": "0.2.0-alpha.1",
                    },
                    "external": {
                        "artifact_name": "evidence",
                        "auditor_principal": self.principal,
                        "authorization_id": "4" * 64,
                        "commit": "b" * 40,
                        "engine_name": "docker",
                        "repository": "independent-owner/audit",
                        "run_attempt": 1,
                        "run_id": 2,
                        "workflow_path": ".github/workflows/audit.yml",
                    },
                    "kind": authorization.POLICY_KIND,
                    "schema_version": 1,
                    "trust": {
                        "allowed_signers_sha256": digest(self.allowed.read_bytes()),
                        "namespace": authorization.NAMESPACE,
                    },
                    "validity": {
                        "not_after": "2026-08-12T00:00:00Z",
                        "not_before": "2026-08-11T00:00:00Z",
                    },
                }
            )
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
                authorization.NAMESPACE,
                str(self.policy),
            ],
            check=True,
            capture_output=True,
        )
        self.config = self.root / "transport.json"
        self.config.write_bytes(
            canonical(
                {
                    "kind": transport.KIND,
                    "schema_version": 1,
                    "transport": {
                        "maximum_bytes": 65536,
                        "policy_url_template": "https://audit.example/v1/{candidate_commit}/{candidate_manifest_sha256_hex}.json",
                        "signature_url_template": "https://audit.example/v1/{candidate_commit}/{candidate_manifest_sha256_hex}.json.sig",
                    },
                    "trust": {
                        "allowed_signers_sha256": digest(self.allowed.read_bytes()),
                        "auditor_principal": self.principal,
                        "namespace": authorization.NAMESPACE,
                    },
                }
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_fetches_only_derived_signed_exact_candidate_policy(self) -> None:
        policy_url, signature_url = transport.render_urls(
            transport.load_transport(self.config, self.allowed)[0],
            candidate_commit=self.commit,
            candidate_manifest_sha256=self.manifest_digest,
        )
        receipt = transport.fetch_policy(
            config=self.config,
            allowed_signers=self.allowed,
            candidate_manifest=self.manifest,
            output_policy=self.root / "output-policy.json",
            output_signature=self.root / "output-policy.json.sig",
            opener=_Opener(
                {
                    policy_url: self.policy.read_bytes(),
                    signature_url: Path(str(self.policy) + ".sig").read_bytes(),
                }
            ),
        )
        self.assertEqual(receipt["candidate"]["manifest_sha256"], self.manifest_digest)
        self.assertEqual(receipt["policy"]["sha256"], digest(self.policy.read_bytes()))
        self.assertEqual(
            (self.root / "output-policy.json").read_bytes(), self.policy.read_bytes()
        )

    def test_rejects_caller_selected_or_unsigned_policy(self) -> None:
        bad_config = json.loads(self.config.read_text(encoding="utf-8"))
        bad_config["transport"]["policy_url_template"] = (
            "https://audit.example/policy.json"
        )
        self.config.write_bytes(canonical(bad_config))
        with self.assertRaisesRegex(ValueError, "candidate identity field"):
            transport.load_transport(self.config, self.allowed)


if __name__ == "__main__":
    unittest.main()
