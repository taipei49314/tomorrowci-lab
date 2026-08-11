#!/usr/bin/env python3
"""Positive and negative tests for repository-owned qualification evidence."""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import validate_external_evidence as contract

PROJECT_REPOSITORY = "taipei49314/tomorrowci-lab"
PROJECT_SHA = "a" * 40
PROJECT_REF = "refs/heads/master"
WORKFLOW_RUN_ID = "123456789"
WORKFLOW_RUN_ATTEMPT = "1"
ENGINE_VERSION = {"docker": "29.0.0", "podman": "4.9.3"}
CANDIDATE_RUN_ID = "987654321"
CANDIDATE_RUN_ATTEMPT = "2"
CANDIDATE_MANIFEST_SHA256 = f"sha256:{'d' * 64}"
OCI_MANIFEST_DIGEST = f"sha256:{'e' * 64}"


def write_candidate_binding(path: Path, archive_path: Path, binary_path: Path) -> None:
    archive_path.write_bytes(b"focused candidate archive\n")
    archive_data = archive_path.read_bytes()
    binary_path.write_bytes(b"focused candidate binary\n")
    binary_data = binary_path.read_bytes()
    value = {
        "candidate": {
            "artifact_digest": f"sha256:{'f' * 64}",
            "artifact_id": 12345,
            "artifact_name": f"release-candidate-dist-attempt-{CANDIDATE_RUN_ATTEMPT}",
            "artifact_size": 4096,
            "cli_payload": {
                "archive_name": archive_path.name,
                "archive_sha256": contract._file_hash(archive_data),
                "archive_size": len(archive_data),
                "binary_sha256": contract._file_hash(binary_data),
                "binary_size": len(binary_data),
                "target": "x86_64-unknown-linux-gnu",
            },
            "manifest_sha256": CANDIDATE_MANIFEST_SHA256,
            "oci_manifest_digest": OCI_MANIFEST_DIGEST,
            "oci_provenance_sha256": f"sha256:{'1' * 64}",
            "run_attempt": CANDIDATE_RUN_ATTEMPT,
            "run_id": CANDIDATE_RUN_ID,
            "source_sha": PROJECT_SHA,
            "version": "0.2.0-alpha.1",
            "workflow": {
                "conclusion": "success",
                "event": "workflow_dispatch",
                "head_branch": "master",
                "head_sha": PROJECT_SHA,
                "path": ".github/workflows/candidate.yml",
                "workflow_name": "release-candidate",
            },
        },
        "kind": contract.BINDING_KIND,
        "qualification": {
            "repository": PROJECT_REPOSITORY,
            "source_ref": PROJECT_REF,
            "source_sha": PROJECT_SHA,
            "workflow_path": contract.WORKFLOW_PATH,
            "workflow_run_attempt": WORKFLOW_RUN_ATTEMPT,
            "workflow_run_id": WORKFLOW_RUN_ID,
        },
        "status": contract.BINDING_STATUS,
    }
    path.write_bytes(contract.canonical_json_bytes(value))


def candidate_api_documents() -> tuple[dict[str, object], dict[str, object]]:
    run = {
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "master",
        "head_sha": PROJECT_SHA,
        "id": int(CANDIDATE_RUN_ID),
        "name": "release-candidate",
        "path": ".github/workflows/candidate.yml",
        "repository": {"full_name": PROJECT_REPOSITORY},
        "run_attempt": int(CANDIDATE_RUN_ATTEMPT),
        "status": "completed",
    }
    artifact_id = 12345
    artifact = {
        "archive_download_url": (
            f"https://api.github.com/repos/{PROJECT_REPOSITORY}/actions/artifacts/"
            f"{artifact_id}/zip"
        ),
        "digest": f"sha256:{'f' * 64}",
        "expired": False,
        "id": artifact_id,
        "name": f"release-candidate-dist-attempt-{CANDIDATE_RUN_ATTEMPT}",
        "size_in_bytes": 4096,
        "workflow_run": {
            "head_branch": "master",
            "head_sha": PROJECT_SHA,
            "id": int(CANDIDATE_RUN_ID),
        },
    }
    return run, {"artifacts": [artifact], "total_count": 1}


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


class EvidenceFixture:
    def __init__(
        self,
        root: Path,
        target_id: str = "node-helmet",
        engine: str = "docker",
        run_id: str = "0123456789ab",
        future_fail: bool = False,
        candidate_binding: Path | None = None,
        candidate_archive: Path | None = None,
        candidate_binary: Path | None = None,
    ) -> None:
        self.root = root
        self.target_id = target_id
        self.engine = engine
        self.engine_version = ENGINE_VERSION[engine]
        self.run_id = run_id
        self.candidate_binding = candidate_binding or (root / "candidate-binding.json")
        self.candidate_archive = candidate_archive or (
            root / "tomorrowci-v0.2.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz"
        )
        self.candidate_binary = candidate_binary or (root / "tomorrowci")
        if not self.candidate_binding.exists():
            write_candidate_binding(
                self.candidate_binding, self.candidate_archive, self.candidate_binary
            )
        self.context = contract._target_context(
            contract.DEFAULT_PREREGISTRATION,
            contract.ROOT,
            target_id,
            engine,
        )
        self.artifact_name = contract.expected_artifact_name(
            target_id, engine, WORKFLOW_RUN_ATTEMPT, PROJECT_SHA
        )
        self.artifact_root = root / self.artifact_name
        self.run_root = self.artifact_root / ".tomorrowci" / "runs" / run_id
        self.run_root.mkdir(parents=True)
        self._write_evidence(future_fail)
        self.refresh_checksums()
        verified, context = self.validate()
        binding, binding_bytes = contract.verify_candidate_binding(
            self.candidate_binding,
            self.candidate_archive,
            self.candidate_binary,
            CANDIDATE_RUN_ID,
            CANDIDATE_RUN_ATTEMPT,
            CANDIDATE_MANIFEST_SHA256,
            PROJECT_SHA,
            OCI_MANIFEST_DIGEST,
            PROJECT_REPOSITORY,
            PROJECT_SHA,
            PROJECT_REF,
            WORKFLOW_RUN_ID,
            WORKFLOW_RUN_ATTEMPT,
        )
        record = contract.build_record(
            verified,
            context,
            binding,
            binding_bytes,
            PROJECT_REPOSITORY,
            PROJECT_SHA,
            PROJECT_REF,
            WORKFLOW_RUN_ID,
            WORKFLOW_RUN_ATTEMPT,
        )
        contract._write_new_canonical(
            self.artifact_root / "qualification-record.json",
            record,
            "test qualification record",
        )

    def _write_json(self, relative: str, value: object) -> None:
        path = self.run_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def _write_evidence(self, future_fail: bool) -> None:
        target = self.context.target
        source = target["source"]
        runtime = target["runtime_axis"]
        normalized = copy.deepcopy(self.context.config)
        config_hash = contract._canonical_hash(normalized)
        candidate_verdict = "FUTURE_FAIL" if future_fail else "FUTURE_PASS"
        candidate_attempt = 3 if future_fail else 1
        frontier = {
            "changed_axes": ["runtime"] if future_fail else [],
            "failure_signature": (
                {
                    "kind": "TestFailure",
                    "normalized_hash": f"sha256:{'b' * 64}",
                    "primary_frame": None,
                    "summary": "focused failure",
                }
                if future_fail
                else None
            ),
            "first_failing_scenario": "candidate" if future_fail else None,
            "grade": "OBSERVED" if future_fail else "INCONCLUSIVE",
            "horizon_label": runtime["candidate"] if future_fail else None,
            "last_passing_scenario": "baseline" if future_fail else "candidate",
            "notes": ["focused fixture"],
            "observed": future_fail,
            "replay_command": (
                f"tomorrowci replay {self.run_id} --scenario candidate"
                if future_fail
                else None
            ),
        }
        image_digest = f"sha256:{'c' * 64}"

        def result(scenario_id: str, verdict: str, attempt: int) -> dict[str, object]:
            return {
                "attempt": attempt,
                "environment": {
                    "engine": self.engine,
                    "engine_version": self.engine_version,
                    "env": copy.deepcopy(contract.SYNTHETIC_GIT_ENV),
                    "image_digest": image_digest,
                    "network_mode": "none",
                    "workdir": "/work",
                },
                "scenario_id": scenario_id,
                "timed_out": False,
                "verdict": verdict,
            }

        run = {
            "baseline": {"runtime": runtime["baseline"]},
            "config_hash": config_hash,
            "detection": {"ecosystem": target["ecosystem"]},
            "evidence_schema_version": 2,
            "frontier": frontier,
            "identity": {
                "adapter_name": target["ecosystem"],
                "adapter_version": "0.2.0-alpha.1",
                "config_hash": config_hash,
                "container_engine": self.engine,
                "container_engine_version": self.engine_version,
                "dirty_tree": False,
                "source_commit": source["commit"],
                "tool_version": "0.2.0-alpha.1",
            },
            "plan": {
                "scenarios": [
                    {"grade": "OBSERVED", "id": "baseline", "is_baseline": True},
                    {"grade": "OBSERVED", "id": "candidate", "is_baseline": False},
                ]
            },
            "repository": {
                "commit_sha": source["commit"],
                "is_disposable_copy": True,
                "source": f"origin:{source['url']}",
            },
            "results": [
                result("baseline", "BASELINE_PASS", 1),
                result("candidate", candidate_verdict, candidate_attempt),
            ],
            "run_id": self.run_id,
            "tool_version": "0.2.0-alpha.1",
        }
        remote = {
            "canonical_origin": f"origin:{source['url']}",
            "clean_tree": True,
            "clone_timeout_seconds": 120,
            "credentials_allowed": False,
            "lfs_allowed": False,
            "max_clone_disk_bytes": 268435456,
            "max_file_bytes": 26214400,
            "max_files": 10000,
            "max_total_bytes": 104857600,
            "moving_ref_allowed": False,
            "redirects_allowed": False,
            "requested_commit": source["commit"],
            "requested_url": source["url"],
            "resolved_commit": source["commit"],
            "schema_version": 2,
            "snapshot_file_count": target["tree_inventory"]["blob_count"],
            "snapshot_total_bytes": target["tree_inventory"]["total_blob_bytes"],
            "submodules_allowed": False,
            "workspace_manifest_sha256": "",
        }
        workspace_manifest = b"{}\n"
        (self.run_root / "workspace-manifest.json").write_bytes(workspace_manifest)
        remote["workspace_manifest_sha256"] = contract._file_hash(workspace_manifest)
        remote["synthetic_git_index"] = {
            "entry_count": target["tree_inventory"]["blob_count"],
            "history_present": False,
            "hooks_present": False,
            "index_sha256": f"sha256:{'e' * 64}",
            "kind": "tomorrowci.synthetic-git-index.v1",
            "object_files_present": False,
            "ref_files_present": False,
            "remotes_present": False,
            "source": "workspace-manifest.json",
            "workspace_manifest_sha256": remote["workspace_manifest_sha256"],
        }
        self._write_json("config.normalized.json", normalized)
        self._write_json("frontier.json", frontier)
        self._write_json("remote-source.json", remote)
        self._write_json("run.json", run)
        (self.run_root / "scenarios" / "baseline").mkdir(parents=True)
        selected = self.run_root / "scenarios" / "candidate"
        selected.mkdir(parents=True)
        signature = f"sha256:{'b' * 64}" if future_fail else None
        original_exit = 1 if future_fail else 0
        for attempt in (1, 2):
            report = {
                "attempt": attempt,
                "dependency_manifest_sha256": None,
                "duration_ms": 10,
                "engine": self.engine,
                "engine_version": self.engine_version,
                "error": None,
                "exit_match": True,
                "fetch_exit": 0,
                "fetch_timeout_seconds": 30,
                "finished_at": "2026-08-11T00:00:01Z",
                "image_tag": "focused:latest",
                "ok": True,
                "original_exit": original_exit,
                "original_signature": signature,
                "phase": "test",
                "recorded_digest": image_digest,
                "replay_exit": original_exit,
                "replay_signature": signature,
                "resolved_digest": image_digest,
                "scenario_id": "candidate",
                "signature_match": True,
                "started_at": "2026-08-11T00:00:00Z",
                "test_timeout_seconds": 30,
                "timed_out": False,
            }
            self._write_json(
                f"scenarios/candidate/replays/attempt-{attempt}/result.json", report
            )
            if attempt == 2:
                self._write_json("scenarios/candidate/replay-result.json", report)

    def refresh_checksums(self) -> None:
        required = [
            "config.normalized.json",
            "frontier.json",
            "remote-source.json",
            "run.json",
            "workspace-manifest.json",
        ]
        lines = [contract.CHECKSUM_HEADER]
        for relative in required:
            digest = contract._file_hash((self.run_root / relative).read_bytes())
            lines.append(f"{digest}  {relative}")
        (self.run_root / "checksums.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
        )

    def mutate_json(self, relative: str, mutate) -> None:
        path = self.run_root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)
        self._write_json(relative, value)
        if relative in {
            "config.normalized.json",
            "frontier.json",
            "remote-source.json",
            "run.json",
            "workspace-manifest.json",
        }:
            self.refresh_checksums()

    def validate(self, required_replays: int = 2):
        return contract.validate_run(
            self.run_root,
            contract.DEFAULT_PREREGISTRATION,
            contract.ROOT,
            self.target_id,
            self.engine,
            self.engine_version,
            required_replays,
            "0.2.0-alpha.1",
        )

    def verify_artifact(self):
        return contract.verify_artifact(
            self.artifact_root,
            self.candidate_binding,
            self.candidate_archive,
            self.candidate_binary,
            CANDIDATE_RUN_ID,
            CANDIDATE_RUN_ATTEMPT,
            CANDIDATE_MANIFEST_SHA256,
            PROJECT_SHA,
            OCI_MANIFEST_DIGEST,
            contract.DEFAULT_PREREGISTRATION,
            contract.ROOT,
            PROJECT_REPOSITORY,
            PROJECT_SHA,
            PROJECT_REF,
            WORKFLOW_RUN_ID,
            WORKFLOW_RUN_ATTEMPT,
        )


class ExternalEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        # Keep Windows test paths below legacy MAX_PATH while retaining the
        # production artifact name's full target/engine/attempt/SHA identity.
        self.temporary = tempfile.TemporaryDirectory(prefix="t-")
        self.root = Path(self.temporary.name)
        self.candidate_binding = self.root / "candidate-binding.json"
        self.candidate_archive = (
            self.root / "tomorrowci-v0.2.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz"
        )
        self.candidate_binary = self.root / "tomorrowci"
        write_candidate_binding(
            self.candidate_binding, self.candidate_archive, self.candidate_binary
        )

    def test_oci_provenance_uses_authoritative_indented_canonical_json(self) -> None:
        provenance = {"z": [1, {"nested": True}], "a": "value"}
        path = self.root / "image-provenance.json"
        path.write_bytes(contract.oci_canonical_json_bytes(provenance))
        actual, data = contract._load_oci_canonical_json(path, "OCI provenance")
        self.assertEqual(actual, provenance)
        self.assertEqual(data, contract.oci_canonical_json_bytes(provenance))

        path.write_bytes(contract.canonical_json_bytes(provenance))
        with self.assertRaisesRegex(ValueError, "canonical OCI"):
            contract._load_oci_canonical_json(path, "OCI provenance")

    def test_candidate_api_identity_is_exact_and_fail_closed(self) -> None:
        run_path = self.root / "candidate-run.json"
        artifacts_path = self.root / "candidate-artifacts.json"
        original_run, original_artifacts = candidate_api_documents()

        def verify(run: object, artifacts: object):
            write_json(run_path, run)
            write_json(artifacts_path, artifacts)
            return contract._candidate_api_identity(
                run_path,
                artifacts_path,
                CANDIDATE_RUN_ID,
                CANDIDATE_RUN_ATTEMPT,
                PROJECT_SHA,
                PROJECT_REPOSITORY,
            )

        identity = verify(original_run, original_artifacts)
        self.assertEqual(identity["run_attempt"], CANDIDATE_RUN_ATTEMPT)
        self.assertEqual(identity["head_sha"], PROJECT_SHA)

        mutations = {
            "attempt": lambda run, _artifacts: run.update({"run_attempt": 3}),
            "head": lambda run, _artifacts: run.update({"head_sha": "b" * 40}),
            "path": lambda run, _artifacts: run.update(
                {"path": ".github/workflows/not-candidate.yml"}
            ),
            "conclusion": lambda run, _artifacts: run.update({"conclusion": "failure"}),
            "digest": lambda _run, artifacts: artifacts["artifacts"][0].update(
                {"digest": "sha256:BAD"}
            ),
            "expired": lambda _run, artifacts: artifacts["artifacts"][0].update(
                {"expired": True}
            ),
            "duplicate": lambda _run, artifacts: artifacts["artifacts"].append(
                copy.deepcopy(artifacts["artifacts"][0])
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                run = copy.deepcopy(original_run)
                artifacts = copy.deepcopy(original_artifacts)
                mutate(run, artifacts)
                if name == "duplicate":
                    artifacts["total_count"] = 2
                with self.assertRaises(ValueError):
                    verify(run, artifacts)

    def test_build_and_verify_binding_cover_exact_candidate_bytes(self) -> None:
        run_path = self.root / "candidate-run.json"
        artifacts_path = self.root / "candidate-artifacts.json"
        run, artifacts = candidate_api_documents()
        write_json(run_path, run)
        write_json(artifacts_path, artifacts)

        candidate_dist = self.root / "candidate-dist"
        candidate_dist.mkdir()
        version = "0.2.0-alpha.1"
        archive_name = f"tomorrowci-v{version}-x86_64-unknown-linux-gnu.tar.gz"
        archive = candidate_dist / archive_name
        archive.write_bytes(b"candidate archive bytes\n")
        binary = self.root / "extracted-tomorrowci"
        binary.write_bytes(b"candidate executable bytes\n")
        provenance = {
            "kind": "tomorrowci.oci-candidate-provenance.v1",
            "oci": {"manifest": {"digest": OCI_MANIFEST_DIGEST}},
            "schema_version": 1,
            "source": {"commit": PROJECT_SHA, "repository": PROJECT_REPOSITORY},
            "status": "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED",
            "version": version,
            "workflow": {
                "run_attempt": int(CANDIDATE_RUN_ATTEMPT),
                "run_id": int(CANDIDATE_RUN_ID),
            },
        }
        provenance_bytes = contract.oci_canonical_json_bytes(provenance)
        (candidate_dist / "image-provenance.json").write_bytes(provenance_bytes)
        manifest = {
            "kind": "tomorrowci.release-candidate.v1",
            "payload": [
                {
                    "name": archive_name,
                    "sha256": contract._file_hash(archive.read_bytes()),
                    "size": archive.stat().st_size,
                },
                {
                    "name": "image-provenance.json",
                    "sha256": contract._file_hash(provenance_bytes),
                    "size": len(provenance_bytes),
                },
            ],
            "schema_version": 1,
            "source": {
                "commit": PROJECT_SHA,
                "dirty": False,
                "ref": PROJECT_REF,
                "repository": PROJECT_REPOSITORY,
            },
            "status": "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED",
            "version": version,
            "workflow": {
                "run_attempt": int(CANDIDATE_RUN_ATTEMPT),
                "run_id": int(CANDIDATE_RUN_ID),
            },
        }
        manifest_path = candidate_dist / "candidate-manifest.json"
        write_json(manifest_path, manifest)
        manifest_digest = contract._file_hash(manifest_path.read_bytes())
        binding = contract.build_candidate_binding(
            candidate_dist,
            run_path,
            artifacts_path,
            binary,
            CANDIDATE_RUN_ID,
            CANDIDATE_RUN_ATTEMPT,
            manifest_digest,
            PROJECT_SHA,
            OCI_MANIFEST_DIGEST,
            PROJECT_REPOSITORY,
            PROJECT_SHA,
            PROJECT_REF,
            WORKFLOW_RUN_ID,
            WORKFLOW_RUN_ATTEMPT,
        )
        binding_path = self.root / "built-binding.json"
        binding_path.write_bytes(contract.canonical_json_bytes(binding))
        contract.verify_candidate_binding(
            binding_path,
            archive,
            binary,
            CANDIDATE_RUN_ID,
            CANDIDATE_RUN_ATTEMPT,
            manifest_digest,
            PROJECT_SHA,
            OCI_MANIFEST_DIGEST,
            PROJECT_REPOSITORY,
            PROJECT_SHA,
            PROJECT_REF,
            WORKFLOW_RUN_ID,
            WORKFLOW_RUN_ATTEMPT,
        )
        binary.write_bytes(b"drifted executable bytes\n")
        with self.assertRaisesRegex(ValueError, "binary"):
            contract.verify_candidate_binding(
                binding_path,
                archive,
                binary,
                CANDIDATE_RUN_ID,
                CANDIDATE_RUN_ATTEMPT,
                manifest_digest,
                PROJECT_SHA,
                OCI_MANIFEST_DIGEST,
                PROJECT_REPOSITORY,
                PROJECT_SHA,
                PROJECT_REF,
                WORKFLOW_RUN_ID,
                WORKFLOW_RUN_ATTEMPT,
            )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_positive_nobreak_artifact(self) -> None:
        fixture = EvidenceFixture(self.root)
        record = fixture.verify_artifact()
        self.assertEqual(record["frontier"]["classification"], "NoBreak")
        self.assertEqual(record["replay"]["count"], 2)
        self.assertEqual(
            [result["classification"] for result in record["results"]],
            ["BaselinePass", "NoBreak"],
        )

    def test_positive_future_fail_artifact(self) -> None:
        fixture = EvidenceFixture(self.root, future_fail=True)
        record = fixture.verify_artifact()
        self.assertEqual(record["frontier"]["classification"], "FutureFail")
        self.assertTrue(record["frontier"]["observed"])

    def test_engine_mismatch_is_rejected(self) -> None:
        fixture = EvidenceFixture(self.root)
        fixture.mutate_json(
            "run.json",
            lambda value: value["identity"].update({"container_engine": "podman"}),
        )
        with self.assertRaisesRegex(ValueError, "engine identity"):
            fixture.validate()

    def test_remote_commit_mismatch_is_rejected(self) -> None:
        fixture = EvidenceFixture(self.root)
        fixture.mutate_json(
            "remote-source.json",
            lambda value: value.update({"resolved_commit": "d" * 40}),
        )
        with self.assertRaisesRegex(ValueError, "resolved_commit"):
            fixture.validate()

    def test_synthetic_git_index_digest_tamper_is_rejected(self) -> None:
        fixture = EvidenceFixture(self.root)
        fixture.mutate_json(
            "remote-source.json",
            lambda value: value["synthetic_git_index"].update(
                {"workspace_manifest_sha256": f"sha256:{'a' * 64}"}
            ),
        )
        with self.assertRaisesRegex(ValueError, "synthetic Git index"):
            fixture.validate()

    def test_synthetic_git_environment_override_is_rejected(self) -> None:
        fixture = EvidenceFixture(self.root)

        def add_override(value: dict[str, object]) -> None:
            value["results"][0]["environment"]["env"]["GIT_DIR"] = "/tmp/forged"

        fixture.mutate_json("run.json", add_override)
        with self.assertRaisesRegex(ValueError, "exact allowlist"):
            fixture.validate()

    def test_remote_schema_v1_downgrade_is_not_qualification_authority(self) -> None:
        fixture = EvidenceFixture(self.root)

        def downgrade_remote(value: dict[str, object]) -> None:
            value["schema_version"] = 1
            del value["synthetic_git_index"]

        fixture.mutate_json("remote-source.json", downgrade_remote)
        for result in json.loads(
            (fixture.run_root / "run.json").read_text(encoding="utf-8")
        )["results"]:
            self.assertEqual(result["environment"]["workdir"], "/work")
        with self.assertRaises(ValueError):
            fixture.validate()

    def test_disqualifying_result_is_rejected(self) -> None:
        fixture = EvidenceFixture(self.root)
        fixture.mutate_json(
            "run.json",
            lambda value: value["results"][1].update({"verdict": "BLOCKED"}),
        )
        with self.assertRaisesRegex(ValueError, "disqualifying verdict BLOCKED"):
            fixture.validate()

    def test_replay_must_be_exactly_two_contiguous_attempts(self) -> None:
        fixture = EvidenceFixture(self.root)
        shutil.rmtree(
            fixture.run_root / "scenarios" / "candidate" / "replays" / "attempt-2"
        )
        with self.assertRaisesRegex(ValueError, "exactly"):
            fixture.validate()

    def test_current_v2_header_is_required(self) -> None:
        fixture = EvidenceFixture(self.root)
        checksums = fixture.run_root / "checksums.txt"
        text = checksums.read_text(encoding="utf-8")
        checksums.write_text(
            text.replace(contract.CHECKSUM_HEADER, "# legacy-checksums", 1),
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(ValueError, "current_v2"):
            fixture.validate()

    def test_artifact_path_identity_is_required(self) -> None:
        fixture = EvidenceFixture(self.root)
        renamed = self.root / f"{fixture.artifact_name}-renamed"
        fixture.artifact_root.rename(renamed)
        with self.assertRaisesRegex(ValueError, "name/path"):
            contract.verify_artifact(
                renamed,
                self.candidate_binding,
                self.candidate_archive,
                self.candidate_binary,
                CANDIDATE_RUN_ID,
                CANDIDATE_RUN_ATTEMPT,
                CANDIDATE_MANIFEST_SHA256,
                PROJECT_SHA,
                OCI_MANIFEST_DIGEST,
                contract.DEFAULT_PREREGISTRATION,
                contract.ROOT,
                PROJECT_REPOSITORY,
                PROJECT_SHA,
                PROJECT_REF,
                WORKFLOW_RUN_ID,
                WORKFLOW_RUN_ATTEMPT,
            )

    def test_duplicate_result_is_rejected(self) -> None:
        fixture = EvidenceFixture(self.root)

        def duplicate(value) -> None:
            value["results"].append(copy.deepcopy(value["results"][1]))

        fixture.mutate_json("run.json", duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate scenario"):
            fixture.validate()

    def test_duplicate_json_key_is_rejected(self) -> None:
        fixture = EvidenceFixture(self.root)
        run_path = fixture.run_root / "run.json"
        run_path.write_text('{"run_id":"one","run_id":"two"}\n', encoding="utf-8")
        fixture.refresh_checksums()
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            fixture.validate()

    def test_six_artifact_summary_is_canonical_and_complete(self) -> None:
        collection = self.root / "collection"
        collection.mkdir()
        targets = ("python-azure-flask", "node-helmet", "rust-human-panic")
        counter = 0
        for target_id in targets:
            for engine in contract.ENGINES:
                counter += 1
                EvidenceFixture(
                    collection,
                    target_id=target_id,
                    engine=engine,
                    run_id=f"{counter:012x}",
                    future_fail=target_id == "rust-human-panic",
                    candidate_binding=self.candidate_binding,
                    candidate_archive=self.candidate_archive,
                    candidate_binary=self.candidate_binary,
                )
        summary = contract.build_summary(
            collection,
            self.candidate_binding,
            self.candidate_archive,
            self.candidate_binary,
            CANDIDATE_RUN_ID,
            CANDIDATE_RUN_ATTEMPT,
            CANDIDATE_MANIFEST_SHA256,
            PROJECT_SHA,
            OCI_MANIFEST_DIGEST,
            contract.DEFAULT_PREREGISTRATION,
            contract.ROOT,
            PROJECT_REPOSITORY,
            PROJECT_SHA,
            PROJECT_REF,
            WORKFLOW_RUN_ID,
            WORKFLOW_RUN_ATTEMPT,
        )
        self.assertEqual(summary["artifact_count"], 6)
        self.assertEqual(summary["status"], contract.STATUS)
        self.assertEqual(
            contract.canonical_json_bytes(summary),
            contract.canonical_json_bytes(
                json.loads(contract.canonical_json_bytes(summary).decode("utf-8"))
            ),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
