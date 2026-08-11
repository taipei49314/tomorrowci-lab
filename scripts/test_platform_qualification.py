#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import platform_qualification as contract
import run_platform_qualification as runner

SHA = "1" * 40
RUN_ID = "abcdef123456"


def write_json(path: Path, value: object) -> None:
    path.write_bytes(contract.canonical_json_bytes(value))


class PlatformQualificationTests(unittest.TestCase):
    def make_source(self, root: Path) -> Path:
        source = root / "fixture"
        (source / "nested").mkdir(parents=True)
        (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
        (source / "nested" / "data.txt").write_text("data\n", encoding="utf-8")
        return source

    def make_metadata(self, root: Path, source: Path) -> Path:
        metadata = root / "metadata"
        metadata.mkdir()
        write_json(
            metadata / "engine-info.json",
            {
                "Architecture": "x86_64",
                "OSType": "linux",
                "OperatingSystem": "Docker Desktop",
                "ServerVersion": "28.0.4",
                "extra": "retained raw engine metadata",
            },
        )
        write_json(metadata / "pre-state.json", {"containers": [], "volumes": []})
        write_json(metadata / "post-state.json", {"containers": [], "volumes": []})
        write_json(
            metadata / "provider-status.json",
            {
                "docker_context": [
                    {
                        "Endpoints": {
                            "docker": {
                                "Host": "npipe:////./pipe/dockerDesktopLinuxEngine",
                                "SkipTLSVerify": False,
                            }
                        },
                        "Metadata": {"Description": "Docker Desktop"},
                        "Name": "desktop-linux",
                        "Storage": {},
                        "TLSMaterial": {},
                    }
                ]
            },
        )
        snapshot = contract.tree_snapshot(source, exclude_internal=True)
        write_json(metadata / "source-before.json", snapshot)
        write_json(metadata / "source-after.json", snapshot)
        for name, value in {
            "doctor.txt": (
                "TomorrowCI doctor\nselected_engine: Docker\nstatus: READY\n"
            ),
            "engine-context.txt": "desktop-linux\n",
            "engine-version.txt": "28.0.4\n",
            "replay-1.txt": "replay: PASS\n",
            "replay-2.txt": "replay: PASS\n",
            "scan.txt": "run_id: abcdef123456\nverdict: FUTURE_FAIL\n",
            "trust.txt": "TomorrowCI trust audit\nstatus: PASS\n",
        }.items():
            (metadata / name).write_text(value, encoding="utf-8", newline="\n")
        return metadata

    def capture(self, metadata: Path) -> dict[str, object]:
        return contract.create_capture(
            metadata_root=metadata,
            platform_id="windows-x86_64-docker-desktop-linux",
            runner_name="ephemeral-windows-01",
            runner_os="Windows",
            runner_arch="X64",
            project_repository="taipei49314/tomorrowci-lab",
            project_source_sha=SHA,
            project_source_ref="refs/heads/master",
            workflow_run_id="12345",
            workflow_run_attempt="1",
        )

    def test_tree_snapshot_is_stable_and_excludes_internal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = self.make_source(Path(raw))
            internal = source / ".tomorrowci"
            internal.mkdir()
            (internal / "ignored.txt").write_text("ignored\n", encoding="utf-8")
            first = contract.tree_snapshot(source, exclude_internal=True)
            (internal / "ignored.txt").write_text("changed\n", encoding="utf-8")
            second = contract.tree_snapshot(source, exclude_internal=True)
            self.assertEqual(first, second)
            self.assertEqual(
                [item["path"] for item in first["files"]], ["app.py", "nested/data.txt"]
            )
            contract._validate_tree_document(first, "test snapshot")
            forged = json.loads(json.dumps(first))
            forged["files"][0]["sha256"] = "sha256:" + "f" * 64
            with self.assertRaisesRegex(ValueError, "aggregate digest"):
                contract._validate_tree_document(forged, "test snapshot")

    def test_tree_snapshot_rejects_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = self.make_source(Path(raw))
            alias = source / "alias.txt"
            try:
                alias.symlink_to(source / "app.py")
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(ValueError, "aliases are forbidden"):
                contract.tree_snapshot(source, exclude_internal=True)

    def test_capture_binds_clean_engine_source_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = self.make_source(root)
            metadata = self.make_metadata(root, source)
            capture = self.capture(metadata)
            self.assertEqual(
                capture["platform_id"], "windows-x86_64-docker-desktop-linux"
            )
            self.assertEqual(capture["engine"]["provider"], "docker-desktop-linux")
            self.assertEqual(capture["workflow"]["source_sha"], SHA)

            (metadata / "engine-context.txt").write_text("default\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "context"):
                self.capture(metadata)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = self.make_source(root)
            metadata = self.make_metadata(root, source)
            (metadata / "engine-version.txt").write_text(
                "999.0.0\n", encoding="utf-8", newline="\n"
            )
            with self.assertRaisesRegex(ValueError, "versions contradict"):
                self.capture(metadata)

    def test_capture_rejects_provider_identity_claims_not_proven_by_status(
        self,
    ) -> None:
        for mutation, message in (
            (
                {
                    "Name": "desktop-linux",
                    "Metadata": {},
                    "Endpoints": {
                        "docker": {
                            "Host": "npipe:////./pipe/dockerDesktopLinuxEngine",
                            "SkipTLSVerify": False,
                        }
                    },
                    "Storage": {},
                    "TLSMaterial": {},
                },
                "description",
            ),
            (
                {
                    "Name": "desktop-linux",
                    "Metadata": {"Description": "Docker Desktop"},
                    "Endpoints": {
                        "docker": {
                            "Host": "tcp://unrelated.example:2376",
                            "SkipTLSVerify": False,
                        }
                    },
                    "Storage": {},
                    "TLSMaterial": {},
                },
                "endpoint identity",
            ),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source = self.make_source(root)
                metadata = self.make_metadata(root, source)
                write_json(
                    metadata / "provider-status.json", {"docker_context": [mutation]}
                )
                with self.assertRaisesRegex(ValueError, message):
                    self.capture(metadata)

    def test_capture_requires_colima_docker_runtime_and_matching_architecture(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = self.make_source(root)
            metadata = self.make_metadata(root, source)
            write_json(
                metadata / "engine-info.json",
                {
                    "Architecture": "aarch64",
                    "OSType": "linux",
                    "OperatingSystem": "Ubuntu 24.04 LTS",
                    "ServerVersion": "28.3.3",
                },
            )
            (metadata / "engine-version.txt").write_text(
                "28.3.3\n", encoding="utf-8", newline="\n"
            )
            (metadata / "engine-context.txt").write_text(
                "colima\n", encoding="utf-8", newline="\n"
            )
            status = {
                "arch": "aarch64",
                "display_name": "colima",
                "docker_socket": "unix:///Users/runner/.colima/default/docker.sock",
                "driver": "VZ",
                "mount_type": "virtiofs",
                "runtime": "docker",
            }
            context = {
                "Endpoints": {
                    "docker": {
                        "Host": status["docker_socket"],
                        "SkipTLSVerify": False,
                    }
                },
                "Metadata": {},
                "Name": "colima",
                "Storage": {},
                "TLSMaterial": {},
            }
            write_json(
                metadata / "provider-status.json",
                {"colima": status, "docker_context": [context]},
            )
            capture = contract.create_capture(
                metadata_root=metadata,
                platform_id="macos-aarch64-colima",
                runner_name="ephemeral-macos-arm64-01",
                runner_os="macOS",
                runner_arch="ARM64",
                project_repository="taipei49314/tomorrowci-lab",
                project_source_sha=SHA,
                project_source_ref="refs/heads/master",
                workflow_run_id="12345",
                workflow_run_attempt="1",
            )
            self.assertEqual(
                capture["engine"]["provider_identity"]["runtime"], "docker"
            )

            status["runtime"] = "containerd"
            write_json(
                metadata / "provider-status.json",
                {"colima": status, "docker_context": [context]},
            )
            with self.assertRaisesRegex(ValueError, "runtime/provider identity"):
                contract.create_capture(
                    metadata_root=metadata,
                    platform_id="macos-aarch64-colima",
                    runner_name="ephemeral-macos-arm64-01",
                    runner_os="macOS",
                    runner_arch="ARM64",
                    project_repository="taipei49314/tomorrowci-lab",
                    project_source_sha=SHA,
                    project_source_ref="refs/heads/master",
                    workflow_run_id="12345",
                    workflow_run_attempt="1",
                )

    def test_capture_rejects_dirty_machine_source_drift_and_nonpass_logs(self) -> None:
        mutations = (
            ("pre-state.json", {"containers": ["old"], "volumes": []}, "pre-existing"),
            (
                "source-after.json",
                {
                    "algorithm": "sha256-tree-v1",
                    "file_count": 0,
                    "files": [],
                    "sha256": "sha256:" + contract.hashlib.sha256().hexdigest(),
                },
                "source tree changed",
            ),
        )
        for name, value, message in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source = self.make_source(root)
                metadata = self.make_metadata(root, source)
                write_json(metadata / name, value)
                with self.assertRaisesRegex(ValueError, message):
                    self.capture(metadata)

        for name, value, message in (
            ("replay-1.txt", "replay: FAIL\n", "first replay"),
            ("scan.txt", "verdict: BLOCKED\n", "contains BLOCKED"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source = self.make_source(root)
                metadata = self.make_metadata(root, source)
                (metadata / name).write_text(value, encoding="utf-8", newline="\n")
                with self.assertRaisesRegex(ValueError, message):
                    self.capture(metadata)

    def test_capture_rejects_wrong_actual_runner_identity_and_duplicate_json(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = self.make_source(root)
            metadata = self.make_metadata(root, source)
            with self.assertRaisesRegex(ValueError, "runner OS/architecture"):
                contract.create_capture(
                    metadata_root=metadata,
                    platform_id="windows-x86_64-docker-desktop-linux",
                    runner_name="wrong",
                    runner_os="macOS",
                    runner_arch="X64",
                    project_repository="taipei49314/tomorrowci-lab",
                    project_source_sha=SHA,
                    project_source_ref="refs/heads/master",
                    workflow_run_id="12345",
                    workflow_run_attempt="1",
                )
            (metadata / "pre-state.json").write_text(
                '{"containers":[],"containers":[],"volumes":[]}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                self.capture(metadata)

    def make_run(self, root: Path) -> Path:
        run_root = root / "fixture" / ".tomorrowci" / "runs" / RUN_ID
        replay = run_root / "scenarios" / "py310-locked" / "replays"
        for attempt in (1, 2):
            attempt_root = replay / f"attempt-{attempt}"
            attempt_root.mkdir(parents=True)
            write_json(
                attempt_root / "result.json",
                {
                    "attempt": attempt,
                    "engine": "docker",
                    "engine_version": "28.0.4",
                    "exit_match": True,
                    "ok": True,
                    "original_exit": 1,
                    "original_signature": "sha256:" + "2" * 64,
                    "recorded_digest": "python@sha256:" + "3" * 64,
                    "replay_exit": 1,
                    "replay_signature": "sha256:" + "2" * 64,
                    "resolved_digest": "python@sha256:" + "3" * 64,
                    "scenario_id": "py310-locked",
                    "signature_match": True,
                },
            )
        (run_root / "checksums.txt").write_text(
            "# tomorrowci-checksums-v2\n", encoding="utf-8", newline="\n"
        )
        environment = {
            "engine": "docker",
            "engine_version": "28.0.4",
            "image_digest": "python@sha256:" + "3" * 64,
        }
        run = {
            "baseline": {"runtime": "3.9"},
            "config_hash": "sha256:" + "4" * 64,
            "detection": {"ecosystem": "python"},
            "evidence_root": str(run_root),
            "evidence_schema_version": 2,
            "finished_at": "2026-08-11T00:00:01Z",
            "frontier": {
                "failure_signature": "sha256:" + "2" * 64,
                "first_failing_scenario": "py310-locked",
                "grade": "OBSERVED",
                "horizon_label": "3.10",
                "last_passing_scenario": "baseline",
                "observed": True,
            },
            "identity": {
                "container_engine": "docker",
                "dirty_tree": False,
                "source_commit": SHA,
                "tool_version": "0.2.0-alpha.1",
            },
            "plan": {"scenarios": []},
            "repository": {"commit_sha": SHA},
            "results": [
                {
                    "environment": environment,
                    "scenario_id": "baseline",
                    "verdict": "BASELINE_PASS",
                },
                {
                    "environment": environment,
                    "scenario_id": "py310-locked",
                    "verdict": "FUTURE_FAIL",
                },
            ],
            "run_id": RUN_ID,
            "started_at": "2026-08-11T00:00:00Z",
            "tool_version": "0.2.0-alpha.1",
        }
        write_json(run_root / "run.json", run)
        return run_root

    @mock.patch("platform_qualification.subprocess.run")
    def test_run_contract_requires_current_observed_replay_twice(
        self, run: mock.Mock
    ) -> None:
        run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="verify: PASS\n", stderr=""
        )
        with tempfile.TemporaryDirectory() as raw:
            run_root = self.make_run(Path(raw))
            result = contract._verify_run(
                run_root,
                Path("tomorrowci.exe"),
                "0.2.0-alpha.1",
                SHA,
                "28.0.4",
            )
            self.assertEqual(result["run_id"], RUN_ID)
            self.assertEqual(result["replay_count"], 2)
            replay = (
                run_root
                / "scenarios"
                / "py310-locked"
                / "replays"
                / "attempt-2"
                / "result.json"
            )
            document = json.loads(replay.read_text(encoding="utf-8"))
            document["signature_match"] = False
            write_json(replay, document)
            with self.assertRaisesRegex(ValueError, "attempt-2"):
                contract._verify_run(
                    run_root,
                    Path("tomorrowci.exe"),
                    "0.2.0-alpha.1",
                    SHA,
                    "28.0.4",
                )

    def test_copy_evidence_rejects_source_drift_during_retention(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = self.make_run(root)
            artifact = root / "artifact"
            artifact.mkdir()
            original_snapshot = runner.contract.tree_snapshot
            source_snapshots = 0

            def snapshot(path: Path, *, exclude_internal: bool) -> object:
                nonlocal source_snapshots
                if path == source:
                    source_snapshots += 1
                    if source_snapshots == 2:
                        (source / "run.json").write_text("{}\n", encoding="utf-8")
                return original_snapshot(path, exclude_internal=exclude_internal)

            with (
                mock.patch(
                    "run_platform_qualification.contract.tree_snapshot",
                    side_effect=snapshot,
                ),
                self.assertRaisesRegex(ValueError, "changed while it was retained"),
            ):
                runner._copy_evidence(source, artifact, RUN_ID)

    def test_manual_workflow_is_read_only_fail_closed_and_retains_three_platforms(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/platform-qualification.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:\n", workflow)
        self.assertIn("permissions:\n  actions: read\n  contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("packages: write", workflow)
        self.assertNotIn("continue-on-error", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        for label in (
            "tomorrowci-docker-desktop-linux",
            "tomorrowci-colima",
            "tomorrowci-ephemeral",
        ):
            self.assertIn(label, workflow)
        for platform_id in contract.PLATFORMS:
            self.assertIn(platform_id, workflow)
            self.assertIn(f"platform-qualification-{platform_id}", workflow)
        self.assertEqual(workflow.count("if: always()"), 3)
        self.assertEqual(workflow.count("retention-days: 90"), 3)
        self.assertEqual(workflow.count("include-hidden-files: true"), 3)
        self.assertIn("verify-artifact", workflow)
        self.assertIn("--oci-manifest-digest", workflow)
        self.assertIn("persist-credentials: false", workflow)
        ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/test_platform_qualification.py", ci)

    def test_platform_config_requires_docker_without_shrinking_fixture(self) -> None:
        root = Path(__file__).resolve().parents[1]
        base = (root / "fixtures/python-runtime-break/.tomorrowci.yml").read_text(
            encoding="utf-8"
        )
        platform = (
            root / "fixtures/python-runtime-break/.tomorrowci-platform.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(base.replace("engine: auto", "engine: docker"), platform)

    def test_top_level_failure_retention_never_creates_a_pass_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "artifact"
            args = mock.Mock(
                artifact_root=artifact,
                candidate_run_attempt="1",
                candidate_run_id="12345",
                candidate_source_sha=SHA,
                platform_id="macos-aarch64-colima",
                project_repository="taipei49314/tomorrowci-lab",
                project_source_sha=SHA,
                workflow_run_attempt="1",
                workflow_run_id="67890",
            )
            artifact.mkdir()
            (artifact / "workflow-preflight.txt").write_bytes(
                runner._workflow_preflight_bytes(args)
            )
            runner._retain_uncaught_failure(args, ValueError("preflight failed"))
            failure = json.loads(
                (artifact / "failure.json").read_text(encoding="utf-8")
            )
            self.assertEqual(failure["status"], "FAIL")
            self.assertEqual(failure["error"], "preflight failed")
            self.assertFalse((artifact / contract.RECORD_NAME).exists())

    def test_workflow_preflight_is_exactly_bound_and_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            artifact = Path(raw) / "artifact"
            artifact.mkdir()
            args = mock.Mock(
                platform_id="macos-x86_64-colima",
                project_repository="taipei49314/tomorrowci-lab",
                project_source_sha=SHA,
                workflow_run_attempt="2",
                workflow_run_id="67890",
            )
            preflight = artifact / "workflow-preflight.txt"
            preflight.write_bytes(runner._workflow_preflight_bytes(args))
            runner._consume_workflow_preflight(artifact, args)
            self.assertEqual(list(artifact.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
