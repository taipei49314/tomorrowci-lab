#!/usr/bin/env python3
"""Validate and execute deterministic, registry-free dependency fixtures.

The trusted `.tomorrowci-dependencies.json` files contain only exact artifact
identities. `fixture-oracle.json` is deliberately separate and is consumed
only by this CI harness; it is never copied into a probe workspace.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_NAMES = (
    "dependency-python",
    "dependency-node",
    "dependency-rust",
)
TRUSTED_MANIFEST = ".tomorrowci-dependencies.json"
FIXTURE_ORACLE = "fixture-oracle.json"
HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_PATTERN = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")


class FixtureError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FixtureError(f"cannot read canonical JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise FixtureError(f"{path} must contain a JSON object")
    return value


def read_json_value(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FixtureError(f"cannot read JSON {path}: {error}") from error


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise FixtureError(f"{label} key mismatch: missing={missing}, extra={extra}")


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise FixtureError(f"{label} must be a nonempty string")
    return value


def require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise FixtureError(f"{label} must be a list of nonempty strings")
    if len(value) != len(set(value)):
        raise FixtureError(f"{label} must not contain duplicates")
    return value


def is_alias(path: Path) -> bool:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & reparse_flag)


def reject_aliases(root: Path) -> None:
    if is_alias(root) or not root.is_dir():
        raise FixtureError(f"fixture root must be a plain directory: {root}")
    pending = [root]
    while pending:
        current = pending.pop()
        for entry in os.scandir(current):
            path = Path(entry.path)
            if is_alias(path):
                raise FixtureError(f"fixture contains a symlink/reparse entry: {path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif not entry.is_file(follow_symlinks=False):
                raise FixtureError(f"fixture contains a non-regular entry: {path}")


def tree_files(root: Path) -> list[tuple[str, Path]]:
    if is_alias(root) or not root.is_dir():
        raise FixtureError(f"dependency source must be a plain directory: {root}")
    files: list[tuple[str, Path]] = []
    pending = [root]
    while pending:
        current = pending.pop()
        for entry in os.scandir(current):
            path = Path(entry.path)
            if is_alias(path):
                raise FixtureError(f"dependency source contains an alias: {path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                relative = path.relative_to(root).as_posix()
                relative.encode("utf-8", errors="strict")
                files.append((relative, path))
            else:
                raise FixtureError(f"dependency source contains a non-regular entry: {path}")
    files.sort(key=lambda item: item[0])
    return files


def sha256_tree_v1(root: Path) -> str:
    canonical = bytearray()
    for relative, path in tree_files(root):
        if is_alias(path) or not path.is_file():
            raise FixtureError(f"dependency source changed while hashing: {path}")
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        canonical.extend(relative.encode("utf-8"))
        canonical.append(0)
        canonical.extend(file_hash.encode("ascii"))
        canonical.append(10)
    return sha256_bytes(bytes(canonical))


def safe_source(fixture: Path, source: str) -> Path:
    pure = PurePosixPath(source)
    if (
        not source
        or "\\" in source
        or pure.is_absolute()
        or any(part in ("", ".", "..") for part in pure.parts)
        or re.match(r"^[A-Za-z]:", source)
    ):
        raise FixtureError(f"dependency source is not a canonical relative path: {source!r}")
    path = fixture.joinpath(*pure.parts)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(fixture.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise FixtureError(f"dependency source escapes or is missing: {source!r}") from error
    return path


def validate_config(fixture: Path, ecosystem: str, runtime: str) -> int:
    path = fixture / ".tomorrowci.yml"
    try:
        config = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise FixtureError(f"cannot read {path}: {error}") from error
    required_snippets = (
        f"  ecosystem: {ecosystem}",
        f'  runtime: "{runtime}"',
        "    max_versions: 0",
        "    latest_allowed: true",
        "  dependencies: locked",
    )
    for snippet in required_snippets:
        if snippet not in config:
            raise FixtureError(f"{path} lacks required pinned setting: {snippet!r}")
    rerun_matches = re.findall(r"(?m)^\s*reruns_on_failure:\s*(\d+)\s*$", config)
    if len(rerun_matches) != 1 or int(rerun_matches[0]) < 3:
        raise FixtureError(
            f"{path} must set reruns_on_failure >= 3 (original plus two reruns) exactly once"
        )
    return int(rerun_matches[0])


def validate_checked_baseline(
    fixture: Path, ecosystem: str, changes: list[dict[str, Any]]
) -> None:
    expected_sources = {change["name"]: change["before"]["source"] for change in changes}
    expected_versions = {change["name"]: change["before"]["version"] for change in changes}
    if ecosystem == "python":
        lines = [
            line.strip()
            for line in (fixture / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        expected = [f"./{source}" for source in expected_sources.values()]
        if lines != expected:
            raise FixtureError(f"Python checked baseline differs from exact before set: {lines}")
    elif ecosystem == "node":
        package = read_json(fixture / "package.json")
        dependencies = package.get("dependencies")
        expected = {name: f"file:{source}" for name, source in expected_sources.items()}
        if dependencies != expected:
            raise FixtureError("Node package.json differs from exact before set")
        lock = read_json(fixture / "package-lock.json")
        packages = lock.get("packages")
        if not isinstance(packages, dict):
            raise FixtureError("Node package-lock.json lacks packages")
        for name, version in expected_versions.items():
            entry = packages.get(f"node_modules/{name}")
            source = expected_sources[name]
            source_entry = packages.get(source)
            if (
                not isinstance(entry, dict)
                or entry.get("resolved") != source
                or entry.get("link") is not True
                or not isinstance(source_entry, dict)
                or source_entry.get("name") != name
                or source_entry.get("version") != version
            ):
                raise FixtureError(f"Node lock does not pin {name}=={version}")
    elif ecosystem == "rust":
        cargo = (fixture / "Cargo.toml").read_text(encoding="utf-8")
        selected_root = fixture / "vendor" / "tomorrowci-selected"
        if selected_root.exists():
            raise FixtureError("Rust fixture must not check in a materialized selected tree")
        for name in expected_sources:
            declaration = f'{name} = {{ path = "vendor/tomorrowci-selected/{name}" }}'
            if declaration not in cargo:
                raise FixtureError(f"Rust Cargo.toml lacks fixed materialization path {declaration}")
        if not (fixture / "Cargo.lock").is_file():
            raise FixtureError("Rust fixture requires a checked Cargo.lock")
    else:
        raise FixtureError(f"unsupported ecosystem: {ecosystem}")


def validate_fixture(fixture: Path) -> dict[str, Any]:
    reject_aliases(fixture)
    manifest_path = fixture / TRUSTED_MANIFEST
    oracle_path = fixture / FIXTURE_ORACLE
    manifest = read_json(manifest_path)
    oracle = read_json(oracle_path)

    require_exact_keys(
        manifest,
        {
            "schema_version",
            "ecosystem",
            "runtime",
            "content_hash_algorithm",
            "baseline",
            "candidate",
        },
        f"{manifest_path} root",
    )
    if manifest["schema_version"] != 1:
        raise FixtureError(f"{manifest_path} schema_version must be 1")
    ecosystem = require_string(manifest["ecosystem"], f"{manifest_path} ecosystem")
    if fixture.name != f"dependency-{ecosystem}":
        raise FixtureError(f"fixture path/ecosystem mismatch: {fixture.name}, {ecosystem}")
    if manifest["content_hash_algorithm"] != "sha256-tree-v1":
        raise FixtureError(f"{manifest_path} must use sha256-tree-v1")

    runtime = manifest["runtime"]
    if not isinstance(runtime, dict):
        raise FixtureError(f"{manifest_path} runtime must be an object")
    require_exact_keys(runtime, {"version", "container_image"}, "runtime")
    runtime_version = require_string(runtime["version"], "runtime.version")
    image = require_string(runtime["container_image"], "runtime.container_image")
    if not IMAGE_PATTERN.fullmatch(image):
        raise FixtureError(f"container image is not digest pinned: {image!r}")

    baseline = manifest["baseline"]
    candidate = manifest["candidate"]
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        raise FixtureError("baseline and candidate must be objects")
    require_exact_keys(baseline, {"set_id"}, "baseline")
    require_exact_keys(candidate, {"set_id", "changes"}, "candidate")
    require_string(baseline["set_id"], "baseline.set_id")
    require_string(candidate["set_id"], "candidate.set_id")
    changes = candidate["changes"]
    if not isinstance(changes, list) or not changes:
        raise FixtureError("candidate.changes must be a nonempty list")

    change_ids: list[str] = []
    change_names: list[str] = []
    content_hashes: dict[str, str] = {}
    for index, change in enumerate(changes):
        if not isinstance(change, dict):
            raise FixtureError(f"candidate.changes[{index}] must be an object")
        require_exact_keys(change, {"id", "name", "before", "after"}, f"change[{index}]")
        change_id = require_string(change["id"], f"change[{index}].id")
        name = require_string(change["name"], f"change[{index}].name")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", change_id):
            raise FixtureError(f"noncanonical dependency change id: {change_id!r}")
        change_ids.append(change_id)
        change_names.append(name)
        for side in ("before", "after"):
            artifact = change[side]
            if not isinstance(artifact, dict):
                raise FixtureError(f"change[{index}].{side} must be an object")
            require_exact_keys(
                artifact,
                {"version", "source", "content_sha256"},
                f"change[{index}].{side}",
            )
            require_string(artifact["version"], f"change[{index}].{side}.version")
            source = require_string(artifact["source"], f"change[{index}].{side}.source")
            declared_hash = require_string(
                artifact["content_sha256"], f"change[{index}].{side}.content_sha256"
            )
            if not HASH_PATTERN.fullmatch(declared_hash):
                raise FixtureError(f"noncanonical content hash: {declared_hash!r}")
            actual_hash = sha256_tree_v1(safe_source(fixture, source))
            if actual_hash != declared_hash:
                raise FixtureError(
                    f"content changed for {ecosystem}/{change_id}/{side}: "
                    f"declared={declared_hash}, actual={actual_hash}"
                )
            content_hashes[f"{change_id}:{side}"] = actual_hash
        if change["before"] == change["after"]:
            raise FixtureError(f"dependency change {change_id} does not change exact identity")
    if len(change_ids) != len(set(change_ids)) or len(change_names) != len(set(change_names)):
        raise FixtureError("dependency change ids and names must be unique")

    require_exact_keys(
        oracle,
        {
            "schema_version",
            "authoritative",
            "purpose",
            "failure_marker",
            "required_change_ids",
            "irrelevant_change_ids",
            "expected_minimal_change_ids",
            "probes",
        },
        f"{oracle_path} root",
    )
    if (
        oracle["schema_version"] != 1
        or oracle["authoritative"] is not False
        or oracle["purpose"] != "ci-fixture-assertions-only"
    ):
        raise FixtureError(f"{oracle_path} must be explicitly non-authoritative")
    marker = require_string(oracle["failure_marker"], "oracle.failure_marker")
    required = require_string_list(oracle["required_change_ids"], "required_change_ids")
    irrelevant = require_string_list(oracle["irrelevant_change_ids"], "irrelevant_change_ids")
    minimal = require_string_list(
        oracle["expected_minimal_change_ids"], "expected_minimal_change_ids"
    )
    if set(required) != set(minimal):
        raise FixtureError("fixture required set and expected minimal set must agree")
    if set(required) & set(irrelevant) or set(required) | set(irrelevant) != set(change_ids):
        raise FixtureError("oracle required/irrelevant classes must partition manifest changes")

    probes = oracle["probes"]
    if not isinstance(probes, list):
        raise FixtureError("oracle.probes must be a list")
    probes_by_id: dict[str, dict[str, Any]] = {}
    for index, probe in enumerate(probes):
        if not isinstance(probe, dict):
            raise FixtureError(f"oracle.probes[{index}] must be an object")
        require_exact_keys(probe, {"id", "change_ids", "expected_verdict"}, f"probe[{index}]")
        probe_id = require_string(probe["id"], f"probe[{index}].id")
        selected = require_string_list(probe["change_ids"], f"probe[{index}].change_ids")
        if not set(selected).issubset(change_ids):
            raise FixtureError(f"probe {probe_id} references unknown changes")
        if probe["expected_verdict"] not in ("PASS", "FAIL"):
            raise FixtureError(f"probe {probe_id} has an invalid expected verdict")
        if probe_id in probes_by_id:
            raise FixtureError(f"duplicate oracle probe id: {probe_id}")
        probes_by_id[probe_id] = probe

    expected_probe_shapes: dict[str, tuple[set[str], str]] = {
        "baseline": (set(), "PASS"),
        "candidate-full": (set(change_ids), "FAIL"),
        "ddmin-minimal": (set(minimal), "FAIL"),
    }
    for change_id in change_ids:
        expected_probe_shapes[f"subtract-{change_id}"] = (
            set(change_ids) - {change_id},
            "PASS" if change_id in required else "FAIL",
        )
    if set(probes_by_id) != set(expected_probe_shapes):
        raise FixtureError(
            f"oracle probe set mismatch: actual={sorted(probes_by_id)}, "
            f"expected={sorted(expected_probe_shapes)}"
        )
    for probe_id, (selected, verdict) in expected_probe_shapes.items():
        probe = probes_by_id[probe_id]
        if set(probe["change_ids"]) != selected or probe["expected_verdict"] != verdict:
            raise FixtureError(f"oracle probe semantics mismatch for {probe_id}")

    validate_checked_baseline(fixture, ecosystem, changes)
    reruns = validate_config(fixture, ecosystem, runtime_version)
    return {
        "fixture": fixture,
        "ecosystem": ecosystem,
        "runtime_version": runtime_version,
        "container_image": image,
        "manifest": manifest,
        "oracle": oracle,
        "reruns_on_failure": reruns,
        "content_hashes": content_hashes,
        "manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
    }


def copy_fixture(source: Path, destination: Path) -> None:
    def ignored(_directory: str, names: list[str]) -> set[str]:
        result = set()
        for name in names:
            if (
                name == FIXTURE_ORACLE
                or name in {".tomorrowci", "node_modules", "target", "__pycache__", ".m2-venv"}
                or name.endswith((".egg-info", ".pyc"))
            ):
                result.add(name)
        return result

    shutil.copytree(source, destination, ignore=ignored)
    destination.parent.chmod(0o755)
    for path in [destination, *destination.rglob("*")]:
        if path.is_dir():
            path.chmod(0o777)
        elif path.is_file():
            path.chmod(0o666)


def selected_artifacts(
    manifest: dict[str, Any], selected_ids: list[str]
) -> tuple[list[dict[str, str]], dict[str, str]]:
    selected = set(selected_ids)
    changes = manifest["candidate"]["changes"]
    if not selected.issubset(change["id"] for change in changes):
        raise FixtureError(f"probe references unknown dependency changes: {sorted(selected)}")
    artifacts: list[dict[str, str]] = []
    versions: dict[str, str] = {}
    for change in changes:
        side = "after" if change["id"] in selected else "before"
        artifact = change[side]
        resolved = {
            "id": change["id"],
            "name": change["name"],
            "version": artifact["version"],
            "source": artifact["source"],
            "content_sha256": artifact["content_sha256"],
        }
        artifacts.append(resolved)
        versions[change["name"]] = artifact["version"]
    return artifacts, versions


def prepare_probe(
    workspace: Path, ecosystem: str, artifacts: list[dict[str, str]], selected_ids: list[str]
) -> None:
    if ecosystem == "python":
        requirements = "".join(f"./{artifact['source']}\n" for artifact in artifacts)
        (workspace / "requirements.m2.txt").write_text(requirements, encoding="utf-8", newline="\n")
    elif ecosystem == "node":
        package_path = workspace / "package.json"
        package = read_json(package_path)
        package["dependencies"] = {
            artifact["name"]: f"file:{artifact['source']}" for artifact in artifacts
        }
        package_path.write_text(
            json.dumps(package, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )
        if selected_ids:
            (workspace / "package-lock.json").unlink(missing_ok=True)
    elif ecosystem == "rust":
        selected_root = workspace / "vendor" / "tomorrowci-selected"
        selected_root.mkdir(parents=True)
        for artifact in artifacts:
            source = workspace.joinpath(*PurePosixPath(artifact["source"]).parts)
            destination = selected_root / artifact["name"]
            shutil.copytree(source, destination)
            actual_hash = sha256_tree_v1(destination)
            if actual_hash != artifact["content_sha256"]:
                raise FixtureError(
                    f"materialized Rust dependency {artifact['name']} changed: "
                    f"expected={artifact['content_sha256']}, actual={actual_hash}"
                )
        if selected_ids:
            (workspace / "Cargo.lock").unlink(missing_ok=True)
    else:
        raise FixtureError(f"unsupported ecosystem: {ecosystem}")


def container_script(ecosystem: str) -> str:
    prefix = 'mkdir -p "$HOME"\n'
    if ecosystem == "python":
        return prefix + """cp -R vendor /tmp/m2-vendor
sed 's#^\\./vendor/#/tmp/m2-vendor/#' requirements.m2.txt > /tmp/requirements.m2.txt
python -m pip install --disable-pip-version-check --no-index --no-deps --no-build-isolation --no-use-pep517 --no-cache-dir --no-compile --target /tmp/m2-site -r /tmp/requirements.m2.txt
python -m pip list --format=json --path /tmp/m2-site > .m2-resolved.json
PYTHONPATH=/tmp/m2-site python test_contract.py
"""
    if ecosystem == "node":
        return prefix + """cp -R . /tmp/m2-work
cd /tmp/m2-work
if [ -f package-lock.json ]; then
  npm ci --offline --ignore-scripts --no-audit --no-fund
else
  npm install --offline --ignore-scripts --no-audit --no-fund --package-lock=true
fi
npm ls --all --json > .m2-resolved.json
cp .m2-resolved.json /work/.m2-resolved.json
npm test
"""
    if ecosystem == "rust":
        return prefix + """cp -R . /tmp/m2-work
cd /tmp/m2-work
if [ ! -f Cargo.lock ]; then
  cargo generate-lockfile --offline
fi
cargo metadata --locked --offline --format-version 1 > .m2-resolved.json
cp .m2-resolved.json /work/.m2-resolved.json
cargo test --locked --offline
"""
    raise FixtureError(f"unsupported ecosystem: {ecosystem}")


def docker_pull(image: str, timeout_seconds: int) -> None:
    result = subprocess.run(
        ["docker", "pull", image],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )
    if result.returncode != 0:
        raise FixtureError(f"docker pull failed for {image}:\n{result.stdout[-8000:]}")


def resolved_versions(ecosystem: str, path: Path, expected: dict[str, str]) -> dict[str, str]:
    data = read_json_value(path)
    if ecosystem == "python":
        if not isinstance(data, list):
            raise FixtureError("pip list resolution must be a JSON list")
        observed = {
            item.get("name", "").lower().replace("_", "-"): item.get("version")
            for item in data
            if isinstance(item, dict)
        }
        normalized_expected = {name.lower().replace("_", "-"): version for name, version in expected.items()}
    elif ecosystem == "node":
        if not isinstance(data, dict):
            raise FixtureError("npm ls resolution must be a JSON object")
        dependencies = data.get("dependencies")
        if not isinstance(dependencies, dict):
            raise FixtureError("npm ls resolution lacks dependencies")
        observed = {
            name: entry.get("version")
            for name, entry in dependencies.items()
            if isinstance(entry, dict)
        }
        normalized_expected = expected
    elif ecosystem == "rust":
        if not isinstance(data, dict):
            raise FixtureError("cargo metadata resolution must be a JSON object")
        packages = data.get("packages")
        if not isinstance(packages, list):
            raise FixtureError("cargo metadata resolution lacks packages")
        observed = {
            item.get("name"): item.get("version")
            for item in packages
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        normalized_expected = expected
    else:
        raise FixtureError(f"unsupported ecosystem: {ecosystem}")
    for name, version in normalized_expected.items():
        if observed.get(name) != version:
            raise FixtureError(
                f"{ecosystem} package manager resolved {name}={observed.get(name)!r}, expected {version!r}"
            )
    return {name: observed[name] for name in sorted(normalized_expected)}


def run_attempt(
    validated: dict[str, Any], probe: dict[str, Any], attempt: int, timeout_seconds: int
) -> dict[str, Any]:
    fixture: Path = validated["fixture"]
    ecosystem: str = validated["ecosystem"]
    selected_ids: list[str] = probe["change_ids"]
    artifacts, expected_versions = selected_artifacts(validated["manifest"], selected_ids)
    with tempfile.TemporaryDirectory(prefix=f"tomorrowci-{ecosystem}-{probe['id']}-{attempt}-") as temp:
        workspace = Path(temp) / "fixture"
        copy_fixture(fixture, workspace)
        prepare_probe(workspace, ecosystem, artifacts, selected_ids)
        command = [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,exec,nosuid,nodev,size=512m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            "256",
            "--memory",
            "2g",
            "--cpus",
            "2",
            "--user",
            "65534:65534",
            "--env",
            "HOME=/tmp/home",
            "--env",
            "PIP_DISABLE_PIP_VERSION_CHECK=1",
            "--env",
            "PIP_NO_INDEX=1",
            "--env",
            "npm_config_offline=true",
            "--env",
            "npm_config_update_notifier=false",
            "--env",
            "CARGO_NET_OFFLINE=true",
            "--env",
            "CARGO_HOME=/tmp/cargo-home",
            "--mount",
            f"type=bind,src={workspace.resolve()},dst=/work",
            "--workdir",
            "/work",
            validated["container_image"],
            "sh",
            "-ceu",
            container_script(ecosystem),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise FixtureError(
                f"{fixture.name}/{probe['id']} attempt {attempt} timed out after {timeout_seconds}s"
            ) from error

        output = completed.stdout
        observed_verdict = "PASS" if completed.returncode == 0 else "FAIL"
        expected_verdict = probe["expected_verdict"]
        marker = validated["oracle"]["failure_marker"]
        if observed_verdict != expected_verdict:
            raise FixtureError(
                f"{fixture.name}/{probe['id']} attempt {attempt}: expected {expected_verdict}, "
                f"observed {observed_verdict}\n{output[-8000:]}"
            )
        if expected_verdict == "FAIL" and marker not in output:
            raise FixtureError(
                f"{fixture.name}/{probe['id']} failed without semantic marker {marker!r}\n"
                f"{output[-8000:]}"
            )
        if expected_verdict == "PASS" and marker in output:
            raise FixtureError(f"{fixture.name}/{probe['id']} passed while emitting failure marker")

        resolution_path = workspace / ".m2-resolved.json"
        if not resolution_path.is_file():
            raise FixtureError(
                f"{fixture.name}/{probe['id']} did not emit native package-manager resolution\n"
                f"{output[-8000:]}"
            )
        versions = resolved_versions(ecosystem, resolution_path, expected_versions)
        marker_lines = sorted(
            {
                " ".join(line.split())
                for line in output.splitlines()
                if marker in line
            }
        )
        failure_hash = None
        if expected_verdict == "FAIL":
            if not marker_lines:
                raise FixtureError(f"{fixture.name}/{probe['id']} has no normalized marker lines")
            failure_hash = sha256_bytes("\n".join(marker_lines).encode("utf-8"))
        return {
            "attempt": attempt,
            "observed_verdict": observed_verdict,
            "failure_hash": failure_hash,
            "resolution_sha256": sha256_bytes(resolution_path.read_bytes()),
            "resolved_versions": versions,
            "output_sha256": sha256_bytes(output.encode("utf-8")),
        }


def run_native_fixture(validated: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    fixture: Path = validated["fixture"]
    probe_results = []
    for probe in validated["oracle"]["probes"]:
        attempts = 1
        if probe["expected_verdict"] == "FAIL":
            attempts = validated["reruns_on_failure"]
        print(
            f"[{fixture.name}] {probe['id']}: {probe['expected_verdict']} x{attempts}",
            flush=True,
        )
        records = [
            run_attempt(validated, probe, attempt, timeout_seconds)
            for attempt in range(1, attempts + 1)
        ]
        resolution_hashes = {record["resolution_sha256"] for record in records}
        if len(resolution_hashes) != 1:
            raise FixtureError(f"{fixture.name}/{probe['id']} resolution changed across reruns")
        if probe["expected_verdict"] == "FAIL":
            failure_hashes = {record["failure_hash"] for record in records}
            if len(failure_hashes) != 1:
                raise FixtureError(f"{fixture.name}/{probe['id']} failure changed across reruns")
        probe_results.append(
            {
                "id": probe["id"],
                "change_ids": probe["change_ids"],
                "expected_verdict": probe["expected_verdict"],
                "attempts": records,
            }
        )
    return {
        "fixture": fixture.relative_to(REPO_ROOT).as_posix(),
        "ecosystem": validated["ecosystem"],
        "runtime_version": validated["runtime_version"],
        "container_image": validated["container_image"],
        "trusted_manifest_sha256": validated["manifest_sha256"],
        "content_hashes": validated["content_hashes"],
        "oracle_authoritative": False,
        "probes": probe_results,
    }


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        action="append",
        choices=FIXTURE_NAMES,
        help="validate only the named fixture (repeatable; default: all)",
    )
    parser.add_argument(
        "--native",
        action="store_true",
        help="run each probe through pip/npm/cargo inside its digest-pinned container",
    )
    parser.add_argument("--output", type=Path, help="write a machine-readable result summary")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.timeout_seconds <= 0:
        print("--timeout-seconds must be positive", file=sys.stderr)
        return 2
    selected = args.fixture or list(FIXTURE_NAMES)
    try:
        validated = []
        for name in selected:
            fixture = REPO_ROOT / "fixtures" / name
            print(f"[{name}] validating identities and non-authoritative oracle", flush=True)
            validated.append(validate_fixture(fixture))

        fixture_results = []
        if args.native:
            if shutil.which("docker") is None:
                raise FixtureError("docker is required for --native")
            pulled: set[str] = set()
            for item in validated:
                image = item["container_image"]
                if image not in pulled:
                    print(f"pulling exact container {image}", flush=True)
                    docker_pull(image, max(args.timeout_seconds, 600))
                    pulled.add(image)
                fixture_results.append(run_native_fixture(item, args.timeout_seconds))
        else:
            fixture_results = [
                {
                    "fixture": item["fixture"].relative_to(REPO_ROOT).as_posix(),
                    "ecosystem": item["ecosystem"],
                    "trusted_manifest_sha256": item["manifest_sha256"],
                    "content_hashes": item["content_hashes"],
                    "oracle_authoritative": False,
                }
                for item in validated
            ]

        summary = {
            "schema_version": 1,
            "native_package_manager_probes": bool(args.native),
            "fixtures": fixture_results,
        }
        if args.output:
            output = args.output if args.output.is_absolute() else REPO_ROOT / args.output
            write_summary(output, summary)
            print(f"wrote {output}", flush=True)
        print(f"dependency fixtures: PASS ({len(fixture_results)} ecosystems)", flush=True)
        return 0
    except (FixtureError, OSError, subprocess.SubprocessError) as error:
        print(f"dependency fixtures: FAIL: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
