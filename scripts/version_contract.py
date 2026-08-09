#!/usr/bin/env python3
"""Validate and print TomorrowCI's authoritative workspace version."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def is_semver(value: object) -> bool:
    if not isinstance(value, str) or not SEMVER.fullmatch(value):
        return False
    without_build = value.split("+", 1)[0]
    prerelease = without_build.split("-", 1)[1] if "-" in without_build else ""
    return all(
        not (identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"))
        for identifier in prerelease.split(".")
        if identifier
    )


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def authoritative_version(root: Path = ROOT) -> str:
    version = load_toml(root / "Cargo.toml")["workspace"]["package"]["version"]
    if not is_semver(version):
        raise ValueError(f"workspace.package.version is not SemVer: {version!r}")
    return version


def workspace_packages(root: Path = ROOT) -> dict[str, str]:
    workspace = load_toml(root / "Cargo.toml")["workspace"]
    expected = authoritative_version(root)
    packages: dict[str, str] = {}
    for member in workspace["members"]:
        manifest = load_toml(root / member / "Cargo.toml")
        package = manifest["package"]
        declared = package.get("version")
        if isinstance(declared, dict) and declared.get("workspace") is True:
            resolved = expected
        elif isinstance(declared, str):
            resolved = declared
        else:
            raise ValueError(f"{member}/Cargo.toml has no resolvable package version")
        packages[package["name"]] = resolved
    return packages


def validate_repository(
    root: Path = ROOT,
    *,
    tag: str | None = None,
    release: bool = False,
) -> str:
    version = authoritative_version(root)
    packages = workspace_packages(root)
    mismatched = sorted(name for name, value in packages.items() if value != version)
    if mismatched:
        raise ValueError(
            f"workspace packages do not resolve to {version}: {', '.join(mismatched)}"
        )

    lock = load_toml(root / "Cargo.lock")
    locked = {entry["name"]: entry["version"] for entry in lock.get("package", [])}
    lock_mismatches = sorted(
        name for name in packages if locked.get(name) != version
    )
    if lock_mismatches:
        raise ValueError(
            "Cargo.lock workspace versions disagree with Cargo.toml: "
            + ", ".join(lock_mismatches)
        )

    if tag is not None and tag != f"v{version}":
        raise ValueError(f"tag {tag!r} must equal authoritative version tag v{version}")

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if release and f"## [{version}]" not in changelog:
        raise ValueError(f"CHANGELOG.md has no release section for {version}")
    if not release and "## [Unreleased]" not in changelog and f"## [{version}]" not in changelog:
        raise ValueError("CHANGELOG.md has neither [Unreleased] nor the workspace version")
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--tag")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args(argv)
    try:
        version = validate_repository(
            args.root.resolve(), tag=args.tag, release=args.release
        )
    except (KeyError, OSError, TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"version-contract: FAIL: {exc}", file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
