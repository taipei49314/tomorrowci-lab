#!/usr/bin/env python3
"""Generate a deterministic CycloneDX inventory from exact Cargo.lock data."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import quote

from version_contract import authoritative_version


ROOT = Path(__file__).resolve().parents[1]


def stable_ref(package: dict, root: Path) -> str:
    source = package.get("source") or "workspace"
    return f"pkg:cargo/{quote(package['name'], safe='')}@{quote(package['version'], safe='')}?source={quote(source, safe='')}"


def component_for(package: dict, checksum: str | None, root: Path) -> dict:
    name = package["name"]
    version = package["version"]
    source = package.get("source") or "workspace"
    identity = stable_ref(package, root)
    component: dict = {
        "type": "library",
        "bom-ref": identity,
        "name": name,
        "version": version,
        "purl": f"pkg:cargo/{quote(name, safe='')}@{quote(version, safe='')}",
        "properties": [{"name": "tomorrowci:cargo:source", "value": source}],
    }
    if checksum:
        component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
    return component


def build_sbom(root: Path = ROOT) -> dict:
    with (root / "Cargo.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    packages_by_id = {package["id"]: package for package in metadata["packages"]}
    root_package = next(
        package for package in metadata["packages"] if package["name"] == "tomorrowci-cli"
    )
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}

    included = {root_package["id"]}
    pending = [root_package["id"]]
    graph: dict[str, list[str]] = {}
    while pending:
        package_id = pending.pop()
        dependencies = sorted(
            {
                dependency["pkg"]
                for dependency in nodes[package_id].get("deps", [])
                if any(kind.get("kind") != "dev" for kind in dependency["dep_kinds"])
            }
        )
        graph[package_id] = dependencies
        for dependency in dependencies:
            if dependency not in included:
                included.add(dependency)
                pending.append(dependency)

    checksum_by_identity = {
        (
            package["name"],
            package["version"],
            package.get("source") or "workspace",
        ): package.get("checksum")
        for package in lock.get("package", [])
    }
    dependencies = sorted(
        (packages_by_id[package_id] for package_id in included if package_id != root_package["id"]),
        key=lambda package: (
            package["name"],
            package["version"],
            package.get("source") or "workspace",
        ),
    )
    components = [
        component_for(
            package,
            checksum_by_identity.get(
                (
                    package["name"],
                    package["version"],
                    package.get("source") or "workspace",
                )
            ),
            root,
        )
        for package in dependencies
    ]
    if not components:
        raise ValueError("Cargo.lock contains no packages")
    if any(component["version"] == "locked" for component in components):
        raise ValueError("placeholder dependency version 'locked' is forbidden")
    root_ref = stable_ref(root_package, root)
    dependency_graph = [
        {
            "ref": stable_ref(packages_by_id[package_id], root),
            "dependsOn": sorted(
                stable_ref(packages_by_id[dependency], root)
                for dependency in graph.get(package_id, [])
                if dependency in included
            ),
        }
        for package_id in sorted(
            included, key=lambda item: stable_ref(packages_by_id[item], root)
        )
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "tomorrowci",
                "version": authoritative_version(root),
            }
        },
        "components": components,
        "dependencies": dependency_graph,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        sbom = build_sbom(args.root.resolve())
        payload = json.dumps(sbom, indent=2, sort_keys=True) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8", newline="\n")
    except (
        KeyError,
        OSError,
        StopIteration,
        subprocess.CalledProcessError,
        TypeError,
        ValueError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"generate-sbom: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"generate-sbom: PASS: {len(sbom['components'])} exact components, "
        f"application {sbom['metadata']['component']['version']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
