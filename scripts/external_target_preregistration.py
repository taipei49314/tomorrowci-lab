#!/usr/bin/env python3
"""Validate frozen targets plus their immutable infrastructure amendment.

The v1 preregistration remains unchanged, NOT_RUN, and deliberately carries no
result authority. This read-only validator also binds the later failed run
observation and infrastructure-only amendment without executing target code.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PREREGISTRATION = (
    ROOT / "docs" / "qualification" / "external-targets" / "preregistration-v1.json"
)
INFRASTRUCTURE_AMENDMENT = PurePosixPath(
    "docs/qualification/external-targets/infrastructure-amendment-v1.json"
)
FAILED_OBSERVATION = PurePosixPath(
    "docs/qualification/external-targets/observations/2026-08-11-run-31467337605.json"
)
EXPECTED_FAILED_OBSERVATION_SHA256 = (
    "sha256:80f0ac842a1ea84547771c06d12e621e2cf5af2374b8160af5ff7169bb881c6f"
)
KIND = "tomorrowci.external-target-preregistration.v1"
STATUS = "NOT_RUN"
REGISTERED_ON = "2026-08-11"
MAX_JSON_BYTES = 1024 * 1024
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
CONFIG_PREFIX = PurePosixPath("docs/qualification/external-targets/configs")

EXPECTED_TARGET_ORDER = [
    "python-azure-flask",
    "node-helmet",
    "rust-human-panic",
]
EXPECTED_SELECTION = {
    "ecosystems": ["python", "node", "rust"],
    "excluded_owner": "taipei49314",
    "result_blind": True,
    "target_ids": EXPECTED_TARGET_ORDER,
    "targets_are_project_fixtures": False,
}
EXPECTED_CANDIDATE_BINDING = {
    "candidate_manifest_sha256": None,
    "candidate_source_sha": None,
    "must_bind_before_execution": True,
    "oci_manifest_digest": None,
    "required_source": "current-default-exact-sha-after-all-tracked-fixes",
    "status": "UNBOUND_NOT_RUN",
}
EXPECTED_OPERATIONAL_ACCEPTANCE = {
    "allowed_observations": ["HORIZON_OBSERVED", "NO_HORIZON_OBSERVED"],
    "candidate_replay_count": 2,
    "disqualifying_conditions": [
        "IDENTITY_FAILURE",
        "INTERNAL_ERROR",
        "REQUIRED_BLOCKED",
        "UNVERIFIABLE",
    ],
    "required_engines": ["docker", "podman"],
    "required_sequence": [
        "scan",
        "verify",
        "replay_candidate",
        "replay_candidate",
        "verify",
    ],
    "result_authority": "separate-immutable-qualification-record",
}
EXPECTED_REMOTE_LIMITS = {
    "allow_credentials": False,
    "allow_lfs": False,
    "allow_redirects": False,
    "allow_submodules": False,
    "allowed_host": "github.com",
    "allowed_protocol": "https",
    "max_clone_bytes": 268_435_456,
    "max_file_bytes": 26_214_400,
    "max_file_count": 10_000,
    "max_source_bytes": 104_857_600,
    "timeout_seconds": 120,
}
EXPECTED_REPLACEMENT_POLICY = {
    "allowed_pre_execution_reasons": [
        "EXACT_COMMIT_UNAVAILABLE",
        "NEWLY_DISCOVERED_PROHIBITED_TREE_OR_LICENSE_CONDITION",
        "REPOSITORY_NO_LONGER_PUBLIC",
    ],
    "original_record_and_observations_retained": True,
    "replacement_after_any_result": "FORBIDDEN",
    "requires_new_reviewed_contract_version": True,
    "result_based_replacement": "FORBIDDEN",
    "status": "NOT_REQUESTED",
}
EXPECTED_RETENTION_SECURITY = {
    "container_socket_to_target": "FORBIDDEN",
    "fetch_network": "GITHUB_AND_PACKAGE_REGISTRIES_ONLY",
    "host_execution": "FORBIDDEN",
    "host_secrets": "FORBIDDEN",
    "privacy_scope": "PUBLIC_REPOSITORY_DATA_ONLY",
    "raw_evidence_minimum_days": 90,
    "retain_original_failures": True,
    "source_license_files_retained": True,
    "target_checkout": "TEMPORARY_EXACT_COMMIT",
    "test_network": "NONE",
}


def _file(
    path: str, git_blob_sha1: str, sha256: str, size_bytes: int
) -> dict[str, object]:
    return {
        "git_blob_sha1": git_blob_sha1,
        "path": path,
        "sha256": sha256,
        "size_bytes": size_bytes,
    }


EXPECTED_TARGETS: dict[str, dict[str, object]] = {
    "python-azure-flask": {
        "config_stem": "python-azure-flask",
        "dependency_policy": {
            "axis_claim": "EXCLUDED",
            "baseline_reproducibility": "UNLOCKED_REQUIREMENTS",
            "lockfiles": [],
            "manifest_paths": ["requirements.txt"],
        },
        "ecosystem": "python",
        "execution_budget": {
            "cpus": 1.0,
            "max_parallel": 1,
            "max_scenarios": 4,
            "memory_mb": 2048,
            "pids_limit": 256,
            "reruns_on_failure": 2,
            "timeout_seconds": 300,
        },
        "license": {
            "expression": "MIT",
            "files": [
                _file(
                    "LICENSE.md",
                    "79656060de00aa4659ad2c276d5be8830664d544",
                    "sha256:d9a1b1e30d633d5732ea18e3cba9538d293ebc53e1a9e4e96ab739e0c5c4f1cb",
                    1140,
                )
            ],
            "source": "repository-license-file",
        },
        "rationale": "Public Flask quickstart with a focused route-discovery command; its unpinned requirement excludes dependency qualification.",
        "runtime_axis": {
            "baseline": "3.11",
            "candidate": "3.12",
            "direction": "future",
        },
        "source": {
            "commit": "5bfb67bffda1a5083e33fec45861de6b55f74e57",
            "repository": "Azure-Samples/msdocs-python-flask-webapp-quickstart",
            "tree": "9a3e0abfd4bbe6044ee94c4f9e3516e7e4968053",
            "url": "https://github.com/Azure-Samples/msdocs-python-flask-webapp-quickstart",
            "visibility": "PUBLIC",
        },
        "test_argv": ["python", "-m", "flask", "--app", "app", "routes"],
        "tree_inventory": {
            "blob_count": 66,
            "max_blob_bytes": 663486,
            "total_blob_bytes": 7558379,
            "tree_api_truncated": False,
        },
    },
    "node-helmet": {
        "config_stem": "node-helmet",
        "dependency_policy": {
            "axis_claim": "EXCLUDED",
            "baseline_reproducibility": "LOCKED",
            "lockfiles": [
                _file(
                    "package-lock.json",
                    "678e18ef4717d21cc9df27708102b52e83d0ef8c",
                    "sha256:732de6e400ac80271c12c8124aa7af3285b9a4c01a14d078c6a53c59065f53e5",
                    239788,
                )
            ],
            "manifest_paths": ["package.json"],
        },
        "ecosystem": "node",
        "execution_budget": {
            "cpus": 2.0,
            "max_parallel": 1,
            "max_scenarios": 4,
            "memory_mb": 4096,
            "pids_limit": 512,
            "reruns_on_failure": 2,
            "timeout_seconds": 600,
        },
        "license": {
            "expression": "MIT",
            "files": [
                _file(
                    "LICENSE",
                    "27bd9478b24b763ad5103c097be02ab168b5441e",
                    "sha256:dd282ebd50392cbba041f6f5a4766a28f01a4ee89ea237cd7a7badc3d7871dc8",
                    1089,
                )
            ],
            "source": "repository-license-file",
        },
        "rationale": "Public npm library with an exact package-lock and a focused Node-native test script across Node 20 and 22.",
        "runtime_axis": {
            "baseline": "20",
            "candidate": "22",
            "direction": "future",
        },
        "source": {
            "commit": "9315aac37eb69d8dd3fe81c67febcebe60d7e97e",
            "repository": "helmetjs/helmet",
            "tree": "9a28a13a551323b1ba5d954e06730f7c9a9313cf",
            "url": "https://github.com/helmetjs/helmet",
            "visibility": "PUBLIC",
        },
        "test_argv": ["npm", "run", "test:node"],
        "tree_inventory": {
            "blob_count": 106,
            "max_blob_bytes": 239788,
            "total_blob_bytes": 442866,
            "tree_api_truncated": False,
        },
    },
    "rust-human-panic": {
        "config_stem": "rust-human-panic",
        "dependency_policy": {
            "axis_claim": "EXCLUDED",
            "baseline_reproducibility": "LOCKED",
            "lockfiles": [
                _file(
                    "Cargo.lock",
                    "13fc7f8ea2916da1e382c45b8c3d68d7a4307baf",
                    "sha256:c1768f6effba3aff876c572312dfb6c17ac0aee623ad771417f346b6bd8740ca",
                    18451,
                )
            ],
            "manifest_paths": ["Cargo.toml"],
        },
        "ecosystem": "rust",
        "execution_budget": {
            "cpus": 2.0,
            "max_parallel": 1,
            "max_scenarios": 4,
            "memory_mb": 4096,
            "pids_limit": 512,
            "reruns_on_failure": 2,
            "timeout_seconds": 900,
        },
        "license": {
            "expression": "MIT OR Apache-2.0",
            "files": [
                _file(
                    "LICENSE-APACHE",
                    "8f71f43fee3f78649d238238cbde51e6d7055c82",
                    "sha256:c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08",
                    11358,
                ),
                _file(
                    "LICENSE-MIT",
                    "a2d01088b6ce55e837a6d193943580f978fb2d2e",
                    "sha256:6efb0476a1cc085077ed49357026d8c173bf33017278ef440f222fb9cbcb66e6",
                    1062,
                ),
            ],
            "source": "workspace-manifest-and-license-files",
        },
        "rationale": "Public Rust CLI library with Cargo.lock and declared MSRV 1.74, observed from a Rust 1.83 baseline.",
        "runtime_axis": {
            "baseline": "1.83",
            "candidate": "1.74",
            "direction": "declared-msrv",
        },
        "source": {
            "commit": "b8915ed30fcfca3300e3796fa35ddd0a9a0a5db7",
            "repository": "rust-cli/human-panic",
            "tree": "e2eb6953dea6bf932f02b6bb7c7fd0b263c9bde5",
            "url": "https://github.com/rust-cli/human-panic",
            "visibility": "PUBLIC",
        },
        "test_argv": ["cargo", "test", "--locked"],
        "tree_inventory": {
            "blob_count": 30,
            "max_blob_bytes": 18451,
            "total_blob_bytes": 99641,
            "tree_api_truncated": False,
        },
    },
}


@dataclass(frozen=True)
class VerifiedPreregistration:
    sha256: str
    infrastructure_amendment_sha256: str
    failed_observation_sha256: str
    status: str
    target_ids: tuple[str, ...]
    config_sha256: tuple[tuple[str, str, str], ...]


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _snapshot(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot stat {label}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be one regular non-symlink file")
    if metadata.st_size > MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds the {MAX_JSON_BYTES}-byte bound")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read {label}: {error}") from error


def load_canonical_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    data = _snapshot(path, label)
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{label} must be UTF-8 without BOM")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not strict UTF-8") from error
    if "\r" in text:
        raise ValueError(f"{label} must use LF line endings")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_nonfinite,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid {label}: {error}") from error
    if type(value) is not dict:
        raise ValueError(f"{label} root must be an object")
    if data != canonical_json_bytes(value):
        raise ValueError(f"{label} is not canonical sorted UTF-8 JSON")
    return value, data


def _object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        raise ValueError(
            f"{label} has an unexpected schema; missing={missing}, unknown={unknown}"
        )
    return value


def _typed_equal(actual: object, expected: object, label: str) -> None:
    if type(actual) is not type(expected):
        raise ValueError(
            f"{label} has the wrong JSON type: "
            f"{type(actual).__name__} != {type(expected).__name__}"
        )
    if type(actual) is dict:
        if set(actual) != set(expected):
            raise ValueError(f"{label} has an unexpected schema")
        for key in expected:
            _typed_equal(actual[key], expected[key], f"{label}.{key}")
        return
    if type(actual) is list:
        if len(actual) != len(expected):
            raise ValueError(f"{label} has an unexpected list length")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            _typed_equal(actual_item, expected_item, f"{label}[{index}]")
        return
    if canonical_json_bytes(actual) != canonical_json_bytes(expected):
        raise ValueError(f"{label} changed: {actual!r} != {expected!r}")


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _positive_float(value: object, label: str) -> float:
    if type(value) is not float or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{label} must be a positive finite JSON float")
    return value


def _safe_relative_path(raw: object, label: str) -> PurePosixPath:
    if type(raw) is not str or not raw or "\\" in raw:
        raise ValueError(f"{label} must be a non-empty canonical POSIX path")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} is not a safe canonical relative path")
    return path


def _validate_hashed_file(value: object, label: str) -> None:
    item = _object(
        value,
        {"git_blob_sha1", "path", "sha256", "size_bytes"},
        label,
    )
    _safe_relative_path(item["path"], f"{label}.path")
    if type(item["git_blob_sha1"]) is not str or not SHA1.fullmatch(
        item["git_blob_sha1"]
    ):
        raise ValueError(f"{label}.git_blob_sha1 must be 40 lowercase hex")
    if type(item["sha256"]) is not str or not SHA256.fullmatch(item["sha256"]):
        raise ValueError(f"{label}.sha256 must be a canonical sha256 digest")
    _positive_int(item["size_bytes"], f"{label}.size_bytes")


def _validate_config_schema(config: object, label: str) -> dict[str, object]:
    cfg = _object(
        config,
        {
            "baseline",
            "candidates",
            "execution",
            "policy",
            "project",
            "report",
            "sandbox",
            "version",
        },
        label,
    )
    _object(cfg["baseline"], {"dependencies", "runtime"}, f"{label}.baseline")
    candidates = _object(
        cfg["candidates"], {"dependencies", "runtime"}, f"{label}.candidates"
    )
    _object(
        candidates["dependencies"],
        {"latest_allowed", "prerelease"},
        f"{label}.candidates.dependencies",
    )
    _object(
        candidates["runtime"],
        {"channels", "max_versions"},
        f"{label}.candidates.runtime",
    )
    _object(
        cfg["execution"],
        {"max_parallel", "max_scenarios", "reruns_on_failure", "timeout_seconds"},
        f"{label}.execution",
    )
    policy = _object(cfg["policy"], {"fail_if"}, f"{label}.policy")
    _object(
        policy["fail_if"],
        {
            "baseline_invalid",
            "blocked_ratio_above",
            "horizon_regression",
            "new_future_failure",
        },
        f"{label}.policy.fail_if",
    )
    _object(
        cfg["project"],
        {"build_command", "ecosystem", "test_command"},
        f"{label}.project",
    )
    _object(cfg["report"], {"html", "json", "sarif"}, f"{label}.report")
    _object(
        cfg["sandbox"],
        {"cpus", "engine", "memory_mb", "network", "pids_limit"},
        f"{label}.sandbox",
    )
    return cfg


def _expected_config(target: dict[str, object], engine: str) -> dict[str, object]:
    budget = target["execution_budget"]
    dependency = target["dependency_policy"]
    runtime = target["runtime_axis"]
    baseline_dependencies = (
        "locked"
        if dependency["baseline_reproducibility"] == "LOCKED"
        else "requirements.txt-unlocked"
    )
    return {
        "baseline": {
            "dependencies": baseline_dependencies,
            "runtime": runtime["baseline"],
        },
        "candidates": {
            "dependencies": {"latest_allowed": False, "prerelease": False},
            "runtime": {"channels": ["stable"], "max_versions": 1},
        },
        "execution": {
            "max_parallel": budget["max_parallel"],
            "max_scenarios": budget["max_scenarios"],
            "reruns_on_failure": budget["reruns_on_failure"],
            "timeout_seconds": budget["timeout_seconds"],
        },
        "policy": {
            "fail_if": {
                "baseline_invalid": True,
                "blocked_ratio_above": 0.0,
                "horizon_regression": True,
                "new_future_failure": True,
            }
        },
        "project": {
            "build_command": "auto",
            "ecosystem": target["ecosystem"],
            "test_command": " ".join(target["test_argv"]),
        },
        "report": {"html": True, "json": True, "sarif": False},
        "sandbox": {
            "cpus": budget["cpus"],
            "engine": engine,
            "memory_mb": budget["memory_mb"],
            "network": "fetch-only",
            "pids_limit": budget["pids_limit"],
        },
        "version": 1,
    }


def _resolve_config(root: Path, raw: object, expected: PurePosixPath) -> Path:
    relative = _safe_relative_path(raw, "config path")
    if relative != expected or relative.parent != CONFIG_PREFIX:
        raise ValueError(f"config path changed: {relative} != {expected}")
    root_resolved = root.resolve()
    path = root.joinpath(*relative.parts)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise ValueError(f"config path escapes or is absent: {relative}") from error
    return resolved


def _validate_configs(
    target_value: dict[str, object],
    expected: dict[str, object],
    root: Path,
) -> list[tuple[str, str, str]]:
    refs = _object(target_value["configs"], {"docker", "podman"}, "target.configs")
    loaded: dict[str, dict[str, object]] = {}
    digests: list[tuple[str, str, str]] = []
    for engine in ("docker", "podman"):
        ref = _object(refs[engine], {"path", "sha256"}, f"target.configs.{engine}")
        stem = expected["config_stem"]
        relative = CONFIG_PREFIX / f"{stem}.{engine}.tomorrowci.json"
        path = _resolve_config(root, ref["path"], relative)
        config, data = load_canonical_json(path, f"{engine} target config")
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if type(ref["sha256"]) is not str or not SHA256.fullmatch(ref["sha256"]):
            raise ValueError(f"target.configs.{engine}.sha256 is malformed")
        if ref["sha256"] != digest:
            raise ValueError(f"{engine} target config digest mismatch")
        loaded[engine] = _validate_config_schema(config, f"{engine} target config")
        _typed_equal(
            loaded[engine],
            _expected_config(expected, engine),
            f"{engine} target config contract",
        )
        digests.append((target_value["id"], engine, digest))

    docker = copy.deepcopy(loaded["docker"])
    podman = copy.deepcopy(loaded["podman"])
    docker["sandbox"]["engine"] = "ENGINE"
    podman["sandbox"]["engine"] = "ENGINE"
    _typed_equal(
        docker,
        podman,
        "Docker and Podman configs (only sandbox.engine may differ)",
    )
    return digests


def _validate_target(
    value: object,
    expected_id: str,
    root: Path,
    limits: dict[str, object],
) -> list[tuple[str, str, str]]:
    target = _object(
        value,
        {
            "configs",
            "dependency_policy",
            "ecosystem",
            "execution_budget",
            "id",
            "license",
            "rationale",
            "runtime_axis",
            "source",
            "status",
            "test_command",
            "tree_inventory",
        },
        f"target {expected_id}",
    )
    if target["id"] != expected_id:
        raise ValueError(
            f"target replacement or reordering is forbidden: {target['id']!r}"
        )
    expected = EXPECTED_TARGETS[expected_id]
    if target["status"] != STATUS:
        raise ValueError(f"target {expected_id} status must remain NOT_RUN")
    if type(target["rationale"]) is not str or not target["rationale"].strip():
        raise ValueError(f"target {expected_id} rationale must be non-empty")
    _typed_equal(
        target["rationale"],
        expected["rationale"],
        f"target {expected_id} frozen rationale",
    )

    source = _object(
        target["source"],
        {"commit", "repository", "tree", "url", "visibility"},
        f"target {expected_id}.source",
    )
    if type(source["repository"]) is not str or not REPOSITORY.fullmatch(
        source["repository"]
    ):
        raise ValueError(f"target {expected_id} repository is not canonical")
    if type(source["commit"]) is not str or not SHA1.fullmatch(source["commit"]):
        raise ValueError(
            f"target {expected_id} commit must be an exact 40-lowercase-hex object, not a moving ref"
        )
    if type(source["tree"]) is not str or not SHA1.fullmatch(source["tree"]):
        raise ValueError(f"target {expected_id} tree must be exact 40-lowercase-hex")
    expected_url = f"https://github.com/{source['repository']}"
    if source["url"] != expected_url or source["visibility"] != "PUBLIC":
        raise ValueError(
            f"target {expected_id} source is not one canonical public GitHub repo"
        )
    owner = source["repository"].split("/", 1)[0]
    if owner.casefold() == EXPECTED_SELECTION["excluded_owner"].casefold():
        raise ValueError(f"target {expected_id} is owned by the excluded project owner")
    _typed_equal(source, expected["source"], f"target {expected_id} frozen source")

    inventory = _object(
        target["tree_inventory"],
        {"blob_count", "max_blob_bytes", "total_blob_bytes", "tree_api_truncated"},
        f"target {expected_id}.tree_inventory",
    )
    if inventory["tree_api_truncated"] is not False:
        raise ValueError(f"target {expected_id} tree inventory must be complete")
    blob_count = _positive_int(inventory["blob_count"], "tree blob_count")
    max_blob = _positive_int(inventory["max_blob_bytes"], "tree max_blob_bytes")
    total = _positive_int(inventory["total_blob_bytes"], "tree total_blob_bytes")
    if blob_count > limits["max_file_count"]:
        raise ValueError(f"target {expected_id} exceeds the file-count limit")
    if max_blob > limits["max_file_bytes"]:
        raise ValueError(f"target {expected_id} exceeds the per-file limit")
    if total > limits["max_source_bytes"]:
        raise ValueError(f"target {expected_id} exceeds the source-byte limit")
    _typed_equal(
        inventory,
        expected["tree_inventory"],
        f"target {expected_id} frozen tree inventory",
    )

    command = _object(
        target["test_command"], {"argv", "shell"}, f"target {expected_id}.test_command"
    )
    if command["shell"] is not False or type(command["argv"]) is not list:
        raise ValueError(
            f"target {expected_id} command must use the non-shell argv contract"
        )
    if not command["argv"] or any(
        type(token) is not str
        or not token
        or any(character.isspace() for character in token)
        for token in command["argv"]
    ):
        raise ValueError(f"target {expected_id} argv contains an unsafe token")
    _typed_equal(command["argv"], expected["test_argv"], f"target {expected_id} argv")

    dependency = _object(
        target["dependency_policy"],
        {"axis_claim", "baseline_reproducibility", "lockfiles", "manifest_paths"},
        f"target {expected_id}.dependency_policy",
    )
    if dependency["axis_claim"] != "EXCLUDED":
        raise ValueError(
            f"target {expected_id} dependency-axis overclaim is forbidden; it is runtime-only"
        )
    if (
        type(dependency["manifest_paths"]) is not list
        or not dependency["manifest_paths"]
    ):
        raise ValueError(f"target {expected_id} must bind its dependency manifest")
    for index, path in enumerate(dependency["manifest_paths"]):
        _safe_relative_path(path, f"target {expected_id} manifest[{index}]")
    if len(set(dependency["manifest_paths"])) != len(dependency["manifest_paths"]):
        raise ValueError(f"target {expected_id} has duplicate dependency manifests")
    if type(dependency["lockfiles"]) is not list:
        raise ValueError(f"target {expected_id} lockfiles must be a list")
    for index, item in enumerate(dependency["lockfiles"]):
        _validate_hashed_file(item, f"target {expected_id} lockfile[{index}]")
    if dependency["baseline_reproducibility"] == "LOCKED":
        if not dependency["lockfiles"]:
            raise ValueError(
                f"target {expected_id} locked baseline requires an exact lockfile"
            )
    elif dependency["baseline_reproducibility"] == "UNLOCKED_REQUIREMENTS":
        if dependency["lockfiles"]:
            raise ValueError(
                f"target {expected_id} unlocked baseline cannot claim lockfiles"
            )
    else:
        raise ValueError(
            f"target {expected_id} dependency baseline mode is unsupported"
        )
    _typed_equal(
        dependency,
        expected["dependency_policy"],
        f"target {expected_id} frozen dependency policy",
    )

    license_value = _object(
        target["license"],
        {"expression", "files", "source"},
        f"target {expected_id}.license",
    )
    if type(license_value["files"]) is not list or not license_value["files"]:
        raise ValueError(f"target {expected_id} must retain license-file identities")
    for index, item in enumerate(license_value["files"]):
        _validate_hashed_file(item, f"target {expected_id} license file[{index}]")
    _typed_equal(license_value, expected["license"], f"target {expected_id} license")

    budget = _object(
        target["execution_budget"],
        {
            "cpus",
            "max_parallel",
            "max_scenarios",
            "memory_mb",
            "pids_limit",
            "reruns_on_failure",
            "timeout_seconds",
        },
        f"target {expected_id}.execution_budget",
    )
    _positive_float(budget["cpus"], f"target {expected_id} cpus")
    for key in (
        "max_parallel",
        "max_scenarios",
        "memory_mb",
        "pids_limit",
        "reruns_on_failure",
        "timeout_seconds",
    ):
        _positive_int(budget[key], f"target {expected_id} {key}")
    _typed_equal(budget, expected["execution_budget"], f"target {expected_id} budget")

    _typed_equal(
        target["ecosystem"], expected["ecosystem"], f"target {expected_id} ecosystem"
    )
    _typed_equal(
        target["runtime_axis"],
        expected["runtime_axis"],
        f"target {expected_id} runtime axis",
    )
    return _validate_configs(target, expected, root)


def verify_preregistration(
    path: Path = DEFAULT_PREREGISTRATION,
    root: Path = ROOT,
) -> VerifiedPreregistration:
    document, data = load_canonical_json(path, "external target preregistration")
    _object(
        document,
        {
            "candidate_binding",
            "kind",
            "operational_acceptance",
            "registered_on",
            "remote_materialization_limits",
            "replacement_policy",
            "retention_security",
            "schema_version",
            "selection",
            "status",
            "targets",
        },
        "external target preregistration",
    )
    if document["kind"] != KIND or type(document["schema_version"]) is not int:
        raise ValueError("external target preregistration schema identity mismatch")
    if document["schema_version"] != 1 or document["status"] != STATUS:
        raise ValueError(
            "external target preregistration must remain version 1 NOT_RUN"
        )
    if (
        type(document["registered_on"]) is not str
        or not DATE.fullmatch(document["registered_on"])
        or document["registered_on"] != REGISTERED_ON
    ):
        raise ValueError(f"registered_on must remain the frozen date {REGISTERED_ON}")

    _typed_equal(
        document["candidate_binding"],
        EXPECTED_CANDIDATE_BINDING,
        "candidate binding",
    )
    _typed_equal(
        document["operational_acceptance"],
        EXPECTED_OPERATIONAL_ACCEPTANCE,
        "operational acceptance",
    )
    _typed_equal(
        document["remote_materialization_limits"],
        EXPECTED_REMOTE_LIMITS,
        "remote materialization limits",
    )
    _typed_equal(
        document["replacement_policy"],
        EXPECTED_REPLACEMENT_POLICY,
        "replacement policy",
    )
    _typed_equal(
        document["retention_security"],
        EXPECTED_RETENTION_SECURITY,
        "retention/security policy",
    )
    _typed_equal(document["selection"], EXPECTED_SELECTION, "frozen target selection")

    targets = document["targets"]
    if type(targets) is not list or len(targets) != len(EXPECTED_TARGET_ORDER):
        raise ValueError("external preregistration must contain exactly three targets")
    ids = []
    config_digests: list[tuple[str, str, str]] = []
    for target, expected_id in zip(targets, EXPECTED_TARGET_ORDER):
        if type(target) is not dict:
            raise ValueError("every external target must be an object")
        ids.append(target.get("id"))
        config_digests.extend(
            _validate_target(
                target,
                expected_id,
                root,
                document["remote_materialization_limits"],
            )
        )
    if ids != EXPECTED_TARGET_ORDER or len(set(ids)) != len(ids):
        raise ValueError("target replacement, reordering, or duplication is forbidden")

    preregistration_sha256 = f"sha256:{hashlib.sha256(data).hexdigest()}"
    amendment_sha256, observation_sha256 = verify_infrastructure_amendment(
        root, preregistration_sha256
    )
    return VerifiedPreregistration(
        sha256=preregistration_sha256,
        infrastructure_amendment_sha256=amendment_sha256,
        failed_observation_sha256=observation_sha256,
        status=STATUS,
        target_ids=tuple(ids),
        config_sha256=tuple(config_digests),
    )


def verify_infrastructure_amendment(
    root: Path, preregistration_sha256: str
) -> tuple[str, str]:
    amendment_path = root.joinpath(*INFRASTRUCTURE_AMENDMENT.parts)
    amendment, amendment_data = load_canonical_json(
        amendment_path, "external qualification infrastructure amendment"
    )
    _object(
        amendment,
        {
            "change",
            "discovery",
            "frozen_target_contract",
            "kind",
            "registered_on",
            "schema_version",
            "scope",
            "status",
        },
        "external qualification infrastructure amendment",
    )
    expected_identity = {
        "kind": "tomorrowci.external-qualification-infrastructure-amendment.v1",
        "registered_on": "2026-08-11",
        "schema_version": 1,
        "scope": "RUNNER_INFRASTRUCTURE_ONLY",
        "status": "IMPLEMENTED_NOT_YET_ACCEPTED_AS_QUALIFICATION",
    }
    for key, expected in expected_identity.items():
        _typed_equal(amendment[key], expected, f"infrastructure amendment.{key}")
    _typed_equal(
        amendment["frozen_target_contract"],
        {
            "config_or_test_command_changed": False,
            "preregistration_sha256": preregistration_sha256,
            "source_commit_changed": False,
            "target_ids_changed": False,
        },
        "infrastructure amendment frozen target contract",
    )
    _typed_equal(
        amendment["change"],
        {
            "container_environment": {
                "forbid_unlisted_git_environment": True,
                "git_config_count": "1",
                "git_config_key_0": "safe.directory",
                "git_config_value_0": "/work",
                "global_config": "/dev/null",
                "system_config": False,
            },
            "git_capability": "PATH_ENUMERATION_ONLY",
            "history": False,
            "hooks": False,
            "index_derivation": "VERIFIED_WORKSPACE_MANIFEST_AND_EXACT_FILE_BYTES",
            "mode": "SYNTHETIC_GIT_INDEX_V1",
            "object_files": False,
            "ref_files": False,
            "remotes": False,
            "replay_must_rederive_exact_index": True,
            "remote_source_schema": 2,
        },
        "infrastructure amendment change",
    )
    discovery = _object(
        amendment["discovery"],
        {"observation_path", "observation_sha256", "run_id"},
        "infrastructure amendment discovery",
    )
    if (
        discovery["observation_path"] != FAILED_OBSERVATION.as_posix()
        or discovery["run_id"] != 31467337605
    ):
        raise ValueError("infrastructure amendment discovery identity changed")
    observation_path = root.joinpath(*FAILED_OBSERVATION.parts)
    observation, observation_data = load_canonical_json(
        observation_path, "failed qualification observation"
    )
    observation_sha256 = f"sha256:{hashlib.sha256(observation_data).hexdigest()}"
    if (
        observation_sha256 != EXPECTED_FAILED_OBSERVATION_SHA256
        or discovery["observation_sha256"] != observation_sha256
    ):
        raise ValueError("failed qualification observation digest mismatch")
    _object(
        observation,
        {
            "candidate",
            "failure",
            "jobs",
            "kind",
            "preregistration_sha256",
            "run",
            "schema_version",
            "status",
        },
        "failed qualification observation",
    )
    if (
        observation["kind"] != "tomorrowci.external-qualification-observation.v1"
        or observation["schema_version"] != 1
        or observation["status"] != "FAILED_OBSERVATION_RETAINED"
        or observation["preregistration_sha256"] != preregistration_sha256
        or type(observation["run"]) is not dict
        or observation["run"].get("id") != 31467337605
        or observation["run"].get("conclusion") != "failure"
        or type(observation["failure"]) is not dict
        or observation["failure"].get("target_id") != "node-helmet"
        or observation["failure"].get("classification") != "BASELINE_INVALID"
        or observation["failure"].get("artifact_uploaded") is not False
    ):
        raise ValueError("failed qualification observation identity changed")
    jobs = observation["jobs"]
    if type(jobs) is not list or len(jobs) != 6:
        raise ValueError("failed qualification observation must retain six matrix jobs")
    node = [job for job in jobs if type(job) is dict and job.get("target_id") == "node-helmet"]
    if len(node) != 2 or any(
        job.get("result") != "BASELINE_INVALID" or job.get("artifact") is not None
        for job in node
    ):
        raise ValueError("failed qualification observation changed Node failures")
    return (
        f"sha256:{hashlib.sha256(amendment_data).hexdigest()}",
        observation_sha256,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Phase-7 external target preregistration without running it"
    )
    parser.add_argument("--preregistration", type=Path, default=DEFAULT_PREREGISTRATION)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        verified = verify_preregistration(args.preregistration, args.root)
    except (OSError, ValueError) as error:
        print(f"external target preregistration: FAIL: {error}", file=sys.stderr)
        return 1
    print("external target preregistration: PASS")
    print(f"status: {verified.status}")
    print(f"sha256: {verified.sha256}")
    print(f"infrastructure_amendment_sha256: {verified.infrastructure_amendment_sha256}")
    print(f"failed_observation_sha256: {verified.failed_observation_sha256}")
    print(f"targets: {','.join(verified.target_ids)}")
    print("preregistration_is_result_authority: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
