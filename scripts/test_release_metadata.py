#!/usr/bin/env python3

from __future__ import annotations

import unittest

from generate_sbom import ROOT, build_sbom
from version_contract import authoritative_version, is_semver, validate_repository


class ReleaseMetadataTests(unittest.TestCase):
    def test_repository_version_contract(self) -> None:
        version = validate_repository(ROOT)
        self.assertEqual(version, authoritative_version(ROOT))

    def test_tag_must_match_exact_version(self) -> None:
        version = authoritative_version(ROOT)
        self.assertEqual(validate_repository(ROOT, tag=f"v{version}"), version)
        with self.assertRaisesRegex(ValueError, "must equal"):
            validate_repository(ROOT, tag="v999.0.0")

    def test_semver_rejects_numeric_prerelease_leading_zero(self) -> None:
        self.assertTrue(is_semver("1.0.0-alpha.1"))
        self.assertFalse(is_semver("1.0.0-01"))

    def test_sbom_uses_exact_lock_versions_and_identities(self) -> None:
        sbom = build_sbom(ROOT)
        components = sbom["components"]
        self.assertGreater(len(components), 1)
        self.assertTrue(all(component["version"] != "locked" for component in components))
        self.assertTrue(all(component["bom-ref"] for component in components))
        self.assertNotIn("tomorrowci-gen-demo", {component["name"] for component in components})
        self.assertIn("dependencies", sbom)
        self.assertEqual(
            sbom["metadata"]["component"]["version"], authoritative_version(ROOT)
        )



if __name__ == "__main__":
    unittest.main()
