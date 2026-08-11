#!/usr/bin/env python3
"""Validate and print TomorrowCI's authoritative workspace version."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
CHANGELOG_HEADING = re.compile(
    r"^ {0,3}##[ \t]+\[(?P<name>[^\]\r\n]+)\]"
    r"(?:[ \t]+-[ \t]+(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2}))?[ \t]*$"
)
FENCE_OPEN = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
HTML_RAW_OPEN = re.compile(
    r"^<(?P<tag>script|pre|style|textarea)(?:[ \t>]|$)", re.IGNORECASE
)
HTML_BLOCK_OPEN = re.compile(
    r"^</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|"
    r"col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|"
    r"footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|"
    r"link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|"
    r"section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)"
    r"(?:[ \t]|/?>|$)",
    re.IGNORECASE,
)
HTML_TAG_OPEN = re.compile(
    r"^</?[A-Za-z][A-Za-z0-9-]*"
    r"(?:[ \t]+[A-Za-z_:][A-Za-z0-9_.:-]*"
    r"(?:[ \t]*=[ \t]*(?:[^ \t\"'=<>]+|'[^']*'|\"[^\"]*\"))?)*"
    r"[ \t]*/?>[ \t]*$"
)


def is_semver(value: object) -> bool:
    if not isinstance(value, str) or not SEMVER.fullmatch(value):
        return False
    without_build = value.split("+", 1)[0]
    prerelease = without_build.split("-", 1)[1] if "-" in without_build else ""
    return all(
        not (
            identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0")
        )
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


def changelog_sections(changelog: str) -> list[tuple[str, date | None]]:
    """Parse canonical release H2 headings outside Markdown code/HTML blocks."""

    sections: list[tuple[str, date | None]] = []
    fence_character: str | None = None
    fence_length = 0
    html_terminator: str | None = None
    lines = changelog.split("\n")
    for index, line in enumerate(lines):
        if fence_character is not None:
            closing = re.fullmatch(
                rf" {{0,3}}{re.escape(fence_character)}{{{fence_length},}}[ \t]*",
                line,
            )
            if closing:
                fence_character = None
                fence_length = 0
            continue

        if html_terminator is not None:
            if html_terminator == "blank":
                if not line.strip():
                    html_terminator = None
            elif html_terminator in line.lower():
                html_terminator = None
            continue

        opening = FENCE_OPEN.fullmatch(line)
        if opening and not (
            opening.group("fence").startswith("`") and "`" in opening.group("info")
        ):
            fence_character = opening.group("fence")[0]
            fence_length = len(opening.group("fence"))
            continue

        stripped = line.lstrip(" ")
        if len(line) - len(stripped) <= 3:
            lowered = stripped.lower()
            if lowered.startswith("<!--"):
                if "-->" not in lowered[4:]:
                    html_terminator = "-->"
                continue
            raw = HTML_RAW_OPEN.match(stripped)
            if raw:
                terminator = f"</{raw.group('tag').lower()}"
                if terminator not in lowered:
                    html_terminator = terminator
                continue
            if lowered.startswith("<![cdata["):
                if "]]>" not in lowered:
                    html_terminator = "]]>"
                continue
            if lowered.startswith("<?"):
                if "?>" not in lowered:
                    html_terminator = "?>"
                continue
            if lowered.startswith("<!"):
                if ">" not in lowered:
                    html_terminator = ">"
                continue
            if HTML_BLOCK_OPEN.match(stripped) or HTML_TAG_OPEN.fullmatch(stripped):
                html_terminator = "blank"
                continue

        heading = CHANGELOG_HEADING.fullmatch(line)
        if not heading:
            continue
        if (
            index == 0
            or lines[index - 1].strip()
            or index + 1 >= len(lines)
            or lines[index + 1].strip()
        ):
            continue
        release_date = heading.group("date")
        parsed_date: date | None = None
        if release_date is not None:
            try:
                parsed_date = date.fromisoformat(release_date)
            except ValueError as exc:
                raise ValueError(
                    f"CHANGELOG.md release date is not a valid YYYY-MM-DD: {release_date}"
                ) from exc
            if parsed_date.isoformat() != release_date:
                raise ValueError(
                    f"CHANGELOG.md release date is not canonical: {release_date}"
                )
        sections.append((heading.group("name"), parsed_date))
    return sections


def changelog_section_count(changelog: str, name: str) -> int:
    """Count true Markdown H2 section headings for one changelog identity."""

    return sum(
        section_name == name for section_name, _date in changelog_sections(changelog)
    )


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
    lock_mismatches = sorted(name for name in packages if locked.get(name) != version)
    if lock_mismatches:
        raise ValueError(
            "Cargo.lock workspace versions disagree with Cargo.toml: "
            + ", ".join(lock_mismatches)
        )

    if tag is not None and tag != f"v{version}":
        raise ValueError(f"tag {tag!r} must equal authoritative version tag v{version}")

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    sections = changelog_sections(changelog)
    version_releases = [
        release_date
        for section_name, release_date in sections
        if section_name == version
    ]
    version_sections = len(version_releases)
    if release and (version_sections != 1 or version_releases[0] is None):
        raise ValueError(
            "CHANGELOG.md must have exactly one dated release section for "
            f"{version}; found {version_sections}"
        )
    if not release and not (
        sum(section_name == "Unreleased" for section_name, _date in sections) == 1
        or version_sections == 1
    ):
        raise ValueError(
            "CHANGELOG.md has neither [Unreleased] nor the workspace version"
        )
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
