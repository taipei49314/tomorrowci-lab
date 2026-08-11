#!/usr/bin/env python3

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIGEST_FROM = re.compile(r"^FROM\s+\S+@sha256:[0-9a-f]{64}(?:\s+AS\s+\S+)?$", re.I)


class ContainerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
        self.candidate_workflow = (ROOT / ".github/workflows/candidate.yml").read_text(
            encoding="utf-8"
        )

    def test_every_base_image_is_digest_pinned(self) -> None:
        sources = [
            line.strip()
            for line in self.containerfile.splitlines()
            if line.strip().upper().startswith("FROM ")
        ]
        self.assertEqual(len(sources), 3)
        self.assertTrue(all(DIGEST_FROM.fullmatch(line) for line in sources), sources)
        self.assertNotIn(":latest", self.containerfile)

    def test_runtime_is_non_root_and_contains_no_build_stage_tools(self) -> None:
        runtime = self.containerfile.split("FROM docker.io/library/debian@", 1)[1]
        self.assertIn("USER 65532:65532", runtime)
        self.assertNotIn("cargo ", runtime)
        self.assertNotIn("rustc", runtime)
        self.assertIn("COPY --from=builder", runtime)
        self.assertIn("COPY --from=docker-cli", runtime)

    def test_runtime_packages_come_from_immutable_snapshot(self) -> None:
        self.assertIn("snapshot.debian.org/archive/debian/20260803T000000Z", self.containerfile)
        self.assertIn(
            "snapshot.debian.org/archive/debian-security/20260803T000000Z",
            self.containerfile,
        )
        self.assertIn("--no-install-recommends", self.containerfile)
        self.assertIn("/var/lib/apt/lists/*", self.containerfile)

    def test_runtime_layer_removes_package_manager_wall_clock_state(self) -> None:
        for path in (
            "/var/cache/apt/*",
            "/var/cache/ldconfig/aux-cache",
            "/var/log/alternatives.log",
            "/var/log/apt",
            "/var/log/dpkg.log",
        ):
            self.assertIn(path, self.containerfile)

    def test_image_identity_and_entrypoint_are_explicit(self) -> None:
        for label in (
            "org.opencontainers.image.source",
            "org.opencontainers.image.revision",
            "org.opencontainers.image.version",
        ):
            self.assertIn(label, self.containerfile)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/tomorrowci"]', self.containerfile)

    def test_docker_context_excludes_generated_and_evidence_trees(self) -> None:
        ignored = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())
        self.assertTrue({".git", "dist", "target", "**/.tomorrowci", "**/node_modules"} <= ignored)

    def test_candidate_builder_and_scanner_are_immutable_and_non_publishing(self) -> None:
        self.assertIn("version: v0.36.1", self.candidate_workflow)
        self.assertIn(
            "moby/buildkit@sha256:"
            "2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
            self.candidate_workflow,
        )
        self.assertIn(
            "aquasec/trivy:0.73.0@sha256:"
            "7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c",
            self.candidate_workflow,
        )
        for exporter_option in (
            "tar=false",
            "rewrite-timestamp=true",
            "oci-mediatypes=true",
            "compression=gzip",
            "compression-level=9",
            "force-compression=true",
            "compatibility-version=30",
        ):
            self.assertIn(exporter_option, self.candidate_workflow)
        self.assertIn("permissions:\n  contents: read", self.candidate_workflow)
        self.assertNotIn("docker push", self.candidate_workflow)
        self.assertNotIn("gh release", self.candidate_workflow)

    def test_candidate_smoke_keeps_reproducibility_gates_fail_closed(self) -> None:
        self.assertIn(
            '$env:RUSTFLAGS = "-C link-arg=/Brepro"', self.candidate_workflow
        )
        self.assertIn(
            "python3 scripts/oci_candidate.py docker-archive",
            self.candidate_workflow,
        )
        self.assertIn(
            '--archive "$upload/tomorrowci-oci-linux-amd64.tar"',
            self.candidate_workflow,
        )
        self.assertIn('--docker-archive "$docker_smoke"', self.candidate_workflow)
        self.assertIn('docker load --input "$docker_smoke"', self.candidate_workflow)
        self.assertNotIn(
            'docker load --input "$upload/tomorrowci-oci-linux-amd64.tar"',
            self.candidate_workflow,
        )


if __name__ == "__main__":
    unittest.main()
