#!/usr/bin/env python3

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from generate_sbom import ROOT, build_sbom
from version_contract import (
    authoritative_version,
    is_semver,
    load_toml,
    validate_repository,
)


class ReleaseMetadataTests(unittest.TestCase):
    def test_repository_version_contract(self) -> None:
        version = validate_repository(ROOT)
        self.assertEqual(version, authoritative_version(ROOT))

    def test_tag_must_match_exact_version(self) -> None:
        version = authoritative_version(ROOT)
        self.assertEqual(validate_repository(ROOT, tag=f"v{version}"), version)
        with self.assertRaisesRegex(ValueError, "must equal"):
            validate_repository(ROOT, tag="v999.0.0")

    def test_release_requires_one_exact_changelog_heading(self) -> None:
        version = authoritative_version(ROOT)
        self.assertEqual(
            validate_repository(ROOT, tag=f"v{version}", release=True), version
        )

        for changelog, error in (
            ("# Changelog\n\n## [Unreleased]\n", "exactly one dated"),
            (
                f"# Changelog\n\nProse mentioning ## [{version}] is not a heading.\n",
                "exactly one dated",
            ),
            (
                (
                    f"# Changelog\n\n## [{version}] - 2026-08-11\n\n"
                    f"## [{version}] - 2026-08-11\n"
                ),
                "exactly one dated",
            ),
            (
                f"# Changelog\n\n```markdown\n## [{version}] - 2026-08-11\n```\n",
                "exactly one dated",
            ),
            (
                f"# Changelog\n\n<!--\n## [{version}] - 2026-08-11\n-->\n",
                "exactly one dated",
            ),
            (
                f"# Changelog\n\n<div>\n## [{version}] - 2026-08-11\n</div>\n",
                "exactly one dated",
            ),
            (
                (
                    f"# Changelog\n\n<div>not Markdown\n"
                    f"## [{version}] - 2026-08-11\n</div>\n"
                ),
                "exactly one dated",
            ),
            (
                (
                    f'# Changelog\n\n<div class="x">not Markdown\n'
                    f"## [{version}] - 2026-08-11\n</div>\n"
                ),
                "exactly one dated",
            ),
            (f"# Changelog\n\n## [{version}]\n", "exactly one dated"),
            (
                f"# Changelog\n\n## [{version}] - 2026-02-30\n",
                "valid YYYY-MM-DD",
            ),
        ):
            with (
                self.subTest(changelog=changelog),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                shutil.copy2(ROOT / "Cargo.toml", root / "Cargo.toml")
                shutil.copy2(ROOT / "Cargo.lock", root / "Cargo.lock")
                workspace = load_toml(ROOT / "Cargo.toml")["workspace"]
                for member in workspace["members"]:
                    destination = root / member / "Cargo.toml"
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / member / "Cargo.toml", destination)
                (root / "CHANGELOG.md").write_text(
                    changelog, encoding="utf-8", newline="\n"
                )
                with self.assertRaisesRegex(ValueError, error):
                    validate_repository(root, tag=f"v{version}", release=True)

    def test_semver_rejects_numeric_prerelease_leading_zero(self) -> None:
        self.assertTrue(is_semver("1.0.0-alpha.1"))
        self.assertFalse(is_semver("1.0.0-01"))

    def test_sbom_uses_exact_lock_versions_and_identities(self) -> None:
        sbom = build_sbom(ROOT)
        components = sbom["components"]
        self.assertGreater(len(components), 1)
        self.assertTrue(
            all(component["version"] != "locked" for component in components)
        )
        self.assertTrue(all(component["bom-ref"] for component in components))
        self.assertNotIn(
            "tomorrowci-gen-demo", {component["name"] for component in components}
        )
        self.assertIn("dependencies", sbom)
        self.assertEqual(
            sbom["metadata"]["component"]["version"], authoritative_version(ROOT)
        )


if __name__ == "__main__":
    unittest.main()
