#!/usr/bin/env python3
"""Validate repository-owned qualification of preregistered public targets.

This helper deliberately does not create or consume external authorization.
The Rust CLI remains the authority for the recursively checksummed current-v2
bundle; this script adds the frozen target/engine/workflow bindings that are
specific to the repository-owned external-qualification workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import external_target_preregistration as preregistration_contract

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PREREGISTRATION = (
    ROOT / "docs" / "qualification" / "external-targets" / "preregistration-v1.json"
)
WORKFLOW_PATH = ".github/workflows/external-qualification.yml"
RECORD_KIND = "tomorrowci.repository-external-target-qualification-record.v1"
SUMMARY_KIND = "tomorrowci.repository-external-target-qualification-summary.v1"
BINDING_KIND = "tomorrowci.repository-external-qualification-candidate-binding.v1"
BINDING_STATUS = "VERIFIED_CANDIDATE_INPUT_ONLY"
STATUS = "OBSERVED_PROJECT_OWNED_ONLY"
SOURCE_REF = "refs/heads/master"
CHECKSUM_HEADER = "# tomorrowci-checksums-v2"
ENGINES = ("docker", "podman")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^(?:[a-z0-9._-]+(?:/[a-z0-9._-]+)*@)?sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[0-9a-f]{12}$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
GITHUB_REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
INTEGER = re.compile(r"^[1-9][0-9]*$")
ALLOWED_RAW_VERDICTS = {"BASELINE_PASS", "FUTURE_PASS", "FUTURE_FAIL"}
DISQUALIFYING_RAW_VERDICTS = {
    "BASELINE_INVALID",
    "BLOCKED",
    "UNSUPPORTED",
    "INCONCLUSIVE",
    "FLAKY",
}
REMOTE_SOURCE_KEYS = {
    "canonical_origin",
    "clean_tree",
    "clone_timeout_seconds",
    "credentials_allowed",
    "lfs_allowed",
    "max_clone_disk_bytes",
    "max_file_bytes",
    "max_files",
    "max_total_bytes",
    "moving_ref_allowed",
    "redirects_allowed",
    "requested_commit",
    "requested_url",
    "resolved_commit",
    "schema_version",
    "snapshot_file_count",
    "snapshot_total_bytes",
    "submodules_allowed",
    "workspace_manifest_sha256",
}
FRONTIER_KEYS = {
    "changed_axes",
    "failure_signature",
    "first_failing_scenario",
    "grade",
    "horizon_label",
    "last_passing_scenario",
    "notes",
    "observed",
    "replay_command",
}
REPLAY_KEYS = {
    "attempt",
    "dependency_manifest_sha256",
    "duration_ms",
    "engine",
    "engine_version",
    "error",
    "exit_match",
    "fetch_exit",
    "fetch_timeout_seconds",
    "finished_at",
    "image_tag",
    "ok",
    "original_exit",
    "original_signature",
    "phase",
    "recorded_digest",
    "replay_exit",
    "replay_signature",
    "resolved_digest",
    "scenario_id",
    "signature_match",
    "started_at",
    "test_timeout_seconds",
    "timed_out",
}


@dataclass(frozen=True)
class FrozenTarget:
    preregistration_sha256: str
    document: dict[str, object]
    target: dict[str, object]
    config: dict[str, object]
    config_path: str
    config_sha256: str


@dataclass(frozen=True)
class VerifiedRun:
    run_id: str
    target_id: str
    engine: str
    engine_version: str
    replay_scenario: str
    result_class: str
    results: tuple[dict[str, object], ...]
    frontier: dict[str, object]
    remote_source: dict[str, object]
    config_hash: str
    checksums_sha256: str
    run_sha256: str
    remote_source_sha256: str
    replay: tuple[dict[str, object], ...]


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def oci_canonical_json_bytes(value: object) -> bytes:
    """Match the authoritative canonical writer in oci_candidate.py exactly."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _file_hash(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _is_alias(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def _snapshot(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is unavailable: {error}") from error
    if _is_alias(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be one plain regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValueError(f"could not snapshot {label}: {error}") from error


def _json_from_bytes(data: bytes, label: str) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not UTF-8") from error
    if text.startswith("\ufeff"):
        raise ValueError(f"{label} must not contain a UTF-8 BOM")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_nonfinite,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} is not strict JSON: {error}") from error
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    return value


def _load_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    data = _snapshot(path, label)
    return _json_from_bytes(data, label), data


def _load_canonical_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    value, data = _load_json(path, label)
    if data != canonical_json_bytes(value):
        raise ValueError(f"{label} is not canonical sorted UTF-8 JSON with one LF")
    return value, data


def _load_oci_canonical_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    value, data = _load_json(path, label)
    if data != oci_canonical_json_bytes(value):
        raise ValueError(
            f"{label} is not canonical OCI sorted indented UTF-8 JSON with one LF"
        )
    return value, data


def _object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        raise ValueError(
            f"{label} keys mismatch: expected {sorted(keys)!r}, got {sorted(actual)!r}"
        )
    return value


def _string(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{label} must be one nonempty exact string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} contains a control character")
    return value


def _positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _safe_relative_path(value: object, label: str) -> PurePosixPath:
    raw = _string(value, label)
    if "\\" in raw or raw.startswith("/") or "//" in raw:
        raise ValueError(f"{label} is not a canonical relative POSIX path")
    path = PurePosixPath(raw)
    if str(path) != raw or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"{label} is not a safe canonical relative path")
    return path


def _plain_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is unavailable: {error}") from error
    if _is_alias(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be one plain directory: {path}")


def _walk_plain_tree(root: Path, label: str) -> None:
    _plain_directory(root, label)
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as error:
            raise ValueError(f"could not inspect {label}: {error}") from error
        for entry in entries:
            if (
                not entry.name
                or entry.name in (".", "..")
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in entry.name
                )
            ):
                raise ValueError(f"{label} contains an unsafe path component")
            metadata = entry.stat(follow_symlinks=False)
            if _is_alias(metadata):
                raise ValueError(
                    f"{label} contains a symlink/reparse point: {entry.path}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(Path(entry.path))
            elif not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"{label} contains a non-regular entry: {entry.path}")


def _resolve_beneath(root: Path, relative: PurePosixPath, label: str) -> Path:
    root = root.resolve(strict=True)
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ValueError(f"{label} is unavailable: {error}") from error
        if _is_alias(metadata):
            raise ValueError(f"{label} traverses a symlink/reparse point")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} escapes the repository root") from error
    return resolved


def _validate_sha(value: object, label: str) -> str:
    raw = _string(value, label)
    if not COMMIT.fullmatch(raw):
        raise ValueError(f"{label} must be exactly 40 lowercase hexadecimal characters")
    return raw


def _validate_digest(value: object, label: str) -> str:
    raw = _string(value, label)
    if not SHA256.fullmatch(raw):
        raise ValueError(f"{label} must be one canonical SHA-256 digest")
    return raw


def _validate_image_digest(value: object, label: str) -> str:
    raw = _string(value, label)
    if not IMAGE_DIGEST.fullmatch(raw):
        raise ValueError(f"{label} must be one canonical immutable image digest")
    return raw


def _validate_repository(value: object, label: str) -> str:
    raw = _string(value, label)
    if not GITHUB_REPOSITORY.fullmatch(raw):
        raise ValueError(f"{label} must be one canonical owner/repository slug")
    return raw


def _validate_integer_string(value: object, label: str) -> str:
    raw = _string(value, label)
    if not INTEGER.fullmatch(raw):
        raise ValueError(f"{label} must be a canonical positive decimal string")
    return raw


def _target_context(
    preregistration_path: Path,
    repository_root: Path,
    target_id: str,
    engine: str,
) -> FrozenTarget:
    if engine not in ENGINES:
        raise ValueError(f"engine must be one of {ENGINES!r}")
    verified = preregistration_contract.verify_preregistration(
        preregistration_path, repository_root
    )
    document, document_bytes = _load_json(
        preregistration_path, "external target preregistration"
    )
    if document_bytes != preregistration_contract.canonical_json_bytes(document):
        raise ValueError("external target preregistration canonical encoding mismatch")
    digest = _file_hash(document_bytes)
    if digest != verified.sha256:
        raise ValueError("preregistration snapshot digest disagrees with its verifier")
    targets = document.get("targets")
    if type(targets) is not list:
        raise ValueError("preregistration targets must be an array")
    matches = [
        target
        for target in targets
        if type(target) is dict and target.get("id") == target_id
    ]
    if len(matches) != 1:
        raise ValueError(f"target {target_id!r} is not uniquely preregistered")
    target = matches[0]
    configs = target.get("configs")
    if type(configs) is not dict or type(configs.get(engine)) is not dict:
        raise ValueError(f"target {target_id!r} has no frozen {engine} config")
    config_entry = configs[engine]
    if set(config_entry) != {"path", "sha256"}:
        raise ValueError("frozen config identity keys mismatch")
    relative = _safe_relative_path(config_entry["path"], "frozen config path")
    config_path = _resolve_beneath(repository_root, relative, "frozen config")
    config, config_bytes = _load_json(config_path, "frozen target config")
    expected_digest = _validate_digest(config_entry["sha256"], "frozen config digest")
    if _file_hash(config_bytes) != expected_digest:
        raise ValueError("frozen target config digest mismatch")
    return FrozenTarget(
        preregistration_sha256=digest,
        document=document,
        target=target,
        config=config,
        config_path=relative.as_posix(),
        config_sha256=expected_digest,
    )


def _verify_checksum_manifest(run_root: Path) -> tuple[str, dict[str, str]]:
    data = _snapshot(run_root / "checksums.txt", "current-v2 root checksums")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("current-v2 root checksums are not UTF-8") from error
    if not text.endswith("\n") or "\r" in text:
        raise ValueError("current-v2 root checksums must use LF and end with one LF")
    lines = text.splitlines()
    if not lines or lines[0] != CHECKSUM_HEADER:
        raise ValueError("evidence is not current_v2")
    entries: dict[str, str] = {}
    previous: str | None = None
    for line in lines[1:]:
        match = re.fullmatch(r"(sha256:[0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ValueError(f"noncanonical current-v2 checksum line: {line!r}")
        digest, raw_path = match.groups()
        relative = _safe_relative_path(raw_path, "checksum path")
        normalized = relative.as_posix()
        if normalized in entries:
            raise ValueError(f"duplicate checksum path: {normalized}")
        if previous is not None and normalized <= previous:
            raise ValueError("current-v2 checksum paths are not strictly ordered")
        previous = normalized
        candidate = _resolve_beneath(run_root, relative, "checksummed evidence file")
        actual = _file_hash(_snapshot(candidate, f"checksummed evidence {normalized}"))
        if actual != digest:
            raise ValueError(f"checksum mismatch for {normalized}")
        entries[normalized] = digest
    required = {
        "config.normalized.json",
        "frontier.json",
        "remote-source.json",
        "run.json",
        "workspace-manifest.json",
    }
    missing = sorted(required - set(entries))
    if missing:
        raise ValueError(f"current-v2 checksums omit required evidence: {missing!r}")
    return _file_hash(data), entries


def _validate_remote_source(
    run_root: Path, context: FrozenTarget
) -> tuple[dict[str, object], str]:
    remote, data = _load_json(run_root / "remote-source.json", "remote source record")
    _object(remote, REMOTE_SOURCE_KEYS, "remote source record")
    source = context.target["source"]
    if type(source) is not dict:
        raise ValueError("preregistered source must be an object")
    expected_repository = _validate_repository(
        source["repository"], "target repository"
    )
    expected_url = f"https://github.com/{expected_repository}"
    expected_commit = _validate_sha(source["commit"], "target commit")
    expected_identity = {
        "schema_version": 1,
        "requested_url": expected_url,
        "canonical_origin": f"origin:{expected_url}",
        "requested_commit": expected_commit,
        "resolved_commit": expected_commit,
        "clean_tree": True,
        "moving_ref_allowed": False,
        "redirects_allowed": False,
        "credentials_allowed": False,
        "submodules_allowed": False,
        "lfs_allowed": False,
    }
    for key, expected in expected_identity.items():
        if type(remote.get(key)) is not type(expected) or remote.get(key) != expected:
            raise ValueError(f"remote source {key} does not match preregistration")
    limits = context.document["remote_materialization_limits"]
    if type(limits) is not dict:
        raise ValueError("preregistered remote limits must be an object")
    limit_mapping = {
        "clone_timeout_seconds": "timeout_seconds",
        "max_files": "max_file_count",
        "max_file_bytes": "max_file_bytes",
        "max_total_bytes": "max_source_bytes",
        "max_clone_disk_bytes": "max_clone_bytes",
    }
    for evidence_key, policy_key in limit_mapping.items():
        expected = limits[policy_key]
        if (
            type(remote.get(evidence_key)) is not int
            or remote[evidence_key] != expected
        ):
            raise ValueError(
                f"remote source {evidence_key} does not match frozen limit"
            )
    inventory = context.target["tree_inventory"]
    if type(inventory) is not dict:
        raise ValueError("preregistered tree inventory must be an object")
    if remote["snapshot_file_count"] != inventory["blob_count"]:
        raise ValueError("remote source file count does not match preregistered tree")
    if remote["snapshot_total_bytes"] != inventory["total_blob_bytes"]:
        raise ValueError("remote source byte count does not match preregistered tree")
    workspace_data = _snapshot(
        run_root / "workspace-manifest.json", "workspace manifest"
    )
    expected_workspace_digest = _validate_digest(
        remote["workspace_manifest_sha256"], "remote workspace manifest digest"
    )
    if _file_hash(workspace_data) != expected_workspace_digest:
        raise ValueError("remote source workspace-manifest digest mismatch")
    return remote, _file_hash(data)


def _validate_results(
    run: dict[str, object],
    frontier_file: dict[str, object],
    context: FrozenTarget,
    engine: str,
    engine_version: str,
) -> tuple[str, tuple[dict[str, object], ...], str, dict[str, object]]:
    plan = run.get("plan")
    if type(plan) is not dict or type(plan.get("scenarios")) is not list:
        raise ValueError("run plan must contain a scenario array")
    scenarios = plan["scenarios"]
    if not scenarios:
        raise ValueError("qualification run has no scenarios")
    results = run.get("results")
    if type(results) is not list or not results:
        raise ValueError("qualification run has no observed results")
    scenario_by_id: dict[str, dict[str, object]] = {}
    ordered_ids: list[str] = []
    for scenario in scenarios:
        if type(scenario) is not dict:
            raise ValueError("every planned scenario must be an object")
        scenario_id = _string(scenario.get("id"), "scenario id")
        if not SAFE_ID.fullmatch(scenario_id) or scenario_id in scenario_by_id:
            raise ValueError(f"unsafe or duplicate scenario id: {scenario_id!r}")
        if scenario.get("grade") != "OBSERVED":
            raise ValueError(f"scenario {scenario_id} is not OBSERVED")
        if type(scenario.get("is_baseline")) is not bool:
            raise ValueError(f"scenario {scenario_id} has no typed baseline flag")
        scenario_by_id[scenario_id] = scenario
        ordered_ids.append(scenario_id)
    result_by_id: dict[str, dict[str, object]] = {}
    observed: list[dict[str, object]] = []
    for result in results:
        if type(result) is not dict:
            raise ValueError("every result must be an object")
        scenario_id = _string(result.get("scenario_id"), "result scenario id")
        if scenario_id not in scenario_by_id or scenario_id in result_by_id:
            raise ValueError(
                f"result has unknown or duplicate scenario id: {scenario_id!r}"
            )
        verdict = _string(result.get("verdict"), f"result {scenario_id} verdict")
        if verdict in DISQUALIFYING_RAW_VERDICTS or verdict not in ALLOWED_RAW_VERDICTS:
            raise ValueError(
                f"result {scenario_id} has disqualifying verdict {verdict}"
            )
        if type(result.get("timed_out")) is not bool or result["timed_out"]:
            raise ValueError(
                f"result {scenario_id} timed out or lacks a typed timeout result"
            )
        environment = result.get("environment")
        if type(environment) is not dict:
            raise ValueError(f"result {scenario_id} has no environment")
        if environment.get("engine") != engine:
            raise ValueError(f"result {scenario_id} engine mismatch")
        if environment.get("engine_version") != engine_version:
            raise ValueError(f"result {scenario_id} engine version mismatch")
        if environment.get("network_mode") != "none":
            raise ValueError(f"result {scenario_id} test network is not none")
        _validate_image_digest(
            environment.get("image_digest"), f"result {scenario_id} image digest"
        )
        attempt = _positive_integer(
            result.get("attempt"), f"result {scenario_id} attempt"
        )
        if verdict == "FUTURE_FAIL" and attempt < 3:
            raise ValueError(
                f"result {scenario_id} FUTURE_FAIL lacks two confirming reruns"
            )
        result_by_id[scenario_id] = result
    if set(result_by_id) != set(scenario_by_id):
        raise ValueError("planned scenarios and observed results are not an exact set")
    baseline_ids = [
        scenario_id
        for scenario_id in ordered_ids
        if scenario_by_id[scenario_id]["is_baseline"] is True
    ]
    if len(baseline_ids) != 1:
        raise ValueError("qualification requires exactly one baseline scenario")
    baseline_id = baseline_ids[0]
    if result_by_id[baseline_id]["verdict"] != "BASELINE_PASS":
        raise ValueError("baseline must be BASELINE_PASS")
    nonbaseline_ids = [
        scenario_id for scenario_id in ordered_ids if scenario_id != baseline_id
    ]
    if not nonbaseline_ids:
        raise ValueError("qualification requires at least one nonbaseline scenario")
    for scenario_id in nonbaseline_ids:
        if result_by_id[scenario_id]["verdict"] == "BASELINE_PASS":
            raise ValueError("a nonbaseline result cannot be BASELINE_PASS")

    frontier = run.get("frontier")
    if type(frontier) is not dict or frontier != frontier_file:
        raise ValueError("run/frontier.json mismatch")
    _object(frontier, FRONTIER_KEYS, "frontier")
    future_failures = [
        scenario_id
        for scenario_id in nonbaseline_ids
        if result_by_id[scenario_id]["verdict"] == "FUTURE_FAIL"
    ]
    runtime_axis = context.target["runtime_axis"]
    if type(runtime_axis) is not dict:
        raise ValueError("preregistered runtime axis must be an object")
    if future_failures:
        replay_scenario = future_failures[0]
        if (
            frontier.get("observed") is not True
            or frontier.get("grade") != "OBSERVED"
            or frontier.get("first_failing_scenario") != replay_scenario
            or frontier.get("horizon_label") != runtime_axis["candidate"]
            or type(frontier.get("failure_signature")) is not dict
            or type(frontier.get("replay_command")) is not str
            or not frontier["replay_command"]
        ):
            raise ValueError("FUTURE_FAIL frontier is not an observed exact horizon")
        result_class = "FutureFail"
    else:
        replay_scenario = nonbaseline_ids[0]
        if (
            frontier.get("observed") is not False
            or frontier.get("grade") != "INCONCLUSIVE"
            or frontier.get("first_failing_scenario") is not None
            or frontier.get("horizon_label") is not None
            or frontier.get("failure_signature") is not None
            or frontier.get("replay_command") is not None
        ):
            raise ValueError("NoBreak frontier is not the canonical no-horizon result")
        result_class = "NoBreak"

    for scenario_id in ordered_ids:
        raw = result_by_id[scenario_id]["verdict"]
        classification = {
            "BASELINE_PASS": "BaselinePass",
            "FUTURE_PASS": "NoBreak",
            "FUTURE_FAIL": "FutureFail",
        }[raw]
        observed.append(
            {
                "classification": classification,
                "raw_verdict": raw,
                "scenario_id": scenario_id,
            }
        )
    return result_class, tuple(observed), replay_scenario, frontier


def _validate_replays(
    run_root: Path,
    scenario_ids: Iterable[str],
    selected_scenario: str,
    engine: str,
    engine_version: str,
    required_count: int,
) -> tuple[dict[str, object], ...]:
    scenarios_root = run_root / "scenarios"
    _plain_directory(scenarios_root, "scenario evidence root")
    reports: list[dict[str, object]] = []
    for scenario_id in scenario_ids:
        scenario_root = scenarios_root / scenario_id
        _plain_directory(scenario_root, f"scenario evidence {scenario_id}")
        replay_root = scenario_root / "replays"
        if scenario_id != selected_scenario:
            if replay_root.exists() or (scenario_root / "replay-result.json").exists():
                raise ValueError(
                    f"unexpected replay evidence for scenario {scenario_id}"
                )
            continue
        if required_count == 0:
            if replay_root.exists() or (scenario_root / "replay-result.json").exists():
                raise ValueError("replay selection requires a pristine scenario")
            continue
        _plain_directory(replay_root, "selected replay root")
        names = sorted(entry.name for entry in replay_root.iterdir())
        expected_names = [
            f"attempt-{number}" for number in range(1, required_count + 1)
        ]
        if names != expected_names:
            raise ValueError(
                f"replay attempts must be exactly {expected_names!r}, got {names!r}"
            )
        for number, name in enumerate(expected_names, start=1):
            attempt_root = replay_root / name
            _plain_directory(attempt_root, f"replay {name}")
            report, _ = _load_json(
                attempt_root / "result.json", f"replay {name} result"
            )
            _object(report, REPLAY_KEYS, f"replay {name} result")
            if (
                report.get("attempt") != number
                or report.get("scenario_id") != selected_scenario
            ):
                raise ValueError(f"replay {name} identity mismatch")
            if (
                report.get("engine") != engine
                or report.get("engine_version") != engine_version
            ):
                raise ValueError(f"replay {name} engine identity mismatch")
            if (
                report.get("ok") is not True
                or report.get("exit_match") is not True
                or report.get("signature_match") is not True
                or report.get("timed_out") is not False
                or report.get("error") is not None
                or report.get("phase") != "test"
                or report.get("fetch_exit") != 0
                or report.get("original_exit") != report.get("replay_exit")
                or report.get("original_signature") != report.get("replay_signature")
                or report.get("recorded_digest") != report.get("resolved_digest")
            ):
                raise ValueError(f"replay {name} is not an exact successful replay")
            _validate_image_digest(
                report.get("recorded_digest"), f"replay {name} image digest"
            )
            reports.append(report)
        latest, _ = _load_json(
            scenario_root / "replay-result.json", "latest replay result"
        )
        if latest != reports[-1]:
            raise ValueError("latest replay result is not exact final attempt")
    return tuple(reports)


def validate_run(
    run_root: Path,
    preregistration_path: Path,
    repository_root: Path,
    target_id: str,
    engine: str,
    engine_version: str,
    required_replays: int,
    expected_tool_version: str,
) -> tuple[VerifiedRun, FrozenTarget]:
    if type(required_replays) is not int or required_replays not in (0, 2):
        raise ValueError("required_replays must be exactly 0 or 2")
    engine_version = _string(engine_version, "engine version")
    expected_tool_version = _string(expected_tool_version, "candidate tool version")
    if len(engine_version.encode("utf-8")) > 256:
        raise ValueError("engine version is unreasonably long")
    _walk_plain_tree(run_root, "qualification run evidence")
    if run_root.parent.name != "runs" or run_root.parent.parent.name != ".tomorrowci":
        raise ValueError("run path must be .tomorrowci/runs/<run-id>")
    if not RUN_ID.fullmatch(run_root.name):
        raise ValueError("run directory name is not one canonical run id")
    context = _target_context(preregistration_path, repository_root, target_id, engine)
    checksums_digest, _ = _verify_checksum_manifest(run_root)
    run, run_bytes = _load_json(run_root / "run.json", "run manifest")
    if run.get("evidence_schema_version") != 2:
        raise ValueError("run is not evidence schema current_v2")
    if run.get("run_id") != run_root.name:
        raise ValueError("run manifest id does not match its directory")
    source = context.target["source"]
    repository = run.get("repository")
    if type(repository) is not dict:
        raise ValueError("run repository identity is missing")
    expected_url = f"https://github.com/{source['repository']}"
    if (
        repository.get("source") != f"origin:{expected_url}"
        or repository.get("commit_sha") != source["commit"]
        or repository.get("is_disposable_copy") is not True
    ):
        raise ValueError(
            "run repository does not match the exact preregistered remote source"
        )
    identity = run.get("identity")
    if type(identity) is not dict:
        raise ValueError("run identity is missing")
    if (
        run.get("tool_version") != expected_tool_version
        or identity.get("tool_version") != expected_tool_version
        or identity.get("adapter_version") != expected_tool_version
        or identity.get("adapter_name") != context.target["ecosystem"]
        or identity.get("source_commit") != source["commit"]
        or identity.get("dirty_tree") is not False
        or identity.get("container_engine") != engine
        or identity.get("container_engine_version") != engine_version
    ):
        raise ValueError("run tool/adapter/source/clean/engine identity mismatch")
    detection = run.get("detection")
    if (
        type(detection) is not dict
        or detection.get("ecosystem") != context.target["ecosystem"]
    ):
        raise ValueError("run ecosystem does not match preregistration")
    baseline = run.get("baseline")
    runtime_axis = context.target["runtime_axis"]
    if (
        type(baseline) is not dict
        or baseline.get("runtime") != runtime_axis["baseline"]
    ):
        raise ValueError("run baseline runtime does not match preregistration")
    normalized_config, _ = _load_json(
        run_root / "config.normalized.json", "normalized run config"
    )
    config_hash = _canonical_hash(normalized_config)
    if (
        run.get("config_hash") != config_hash
        or identity.get("config_hash") != config_hash
    ):
        raise ValueError("run config hash does not bind its normalized config")
    expected_sandbox = context.config.get("sandbox")
    actual_sandbox = normalized_config.get("sandbox")
    if type(expected_sandbox) is not dict or type(actual_sandbox) is not dict:
        raise ValueError("target config has no sandbox object")
    if actual_sandbox.get("engine") != engine or actual_sandbox != expected_sandbox:
        raise ValueError(
            "normalized sandbox config differs from the frozen engine config"
        )
    for key in (
        "baseline",
        "candidates",
        "execution",
        "policy",
        "project",
        "report",
        "version",
    ):
        if normalized_config.get(key) != context.config.get(key):
            raise ValueError(
                f"normalized config field {key} differs from frozen config"
            )
    remote_source, remote_source_digest = _validate_remote_source(run_root, context)
    frontier_file, _ = _load_json(run_root / "frontier.json", "frontier evidence")
    result_class, results, replay_scenario, frontier = _validate_results(
        run, frontier_file, context, engine, engine_version
    )
    scenario_ids = [result["scenario_id"] for result in results]
    replays = _validate_replays(
        run_root,
        scenario_ids,
        replay_scenario,
        engine,
        engine_version,
        required_replays,
    )
    _walk_plain_tree(run_root, "qualification run evidence after validation")
    return (
        VerifiedRun(
            run_id=run_root.name,
            target_id=target_id,
            engine=engine,
            engine_version=engine_version,
            replay_scenario=replay_scenario,
            result_class=result_class,
            results=results,
            frontier=frontier,
            remote_source=remote_source,
            config_hash=config_hash,
            checksums_sha256=checksums_digest,
            run_sha256=_file_hash(run_bytes),
            remote_source_sha256=remote_source_digest,
            replay=replays,
        ),
        context,
    )


def expected_artifact_name(
    target_id: str, engine: str, run_attempt: str, project_source_sha: str
) -> str:
    return (
        f"external-qualification-{target_id}-{engine}-attempt-{run_attempt}"
        f"-source-{project_source_sha}"
    )


def _validate_project_identity(
    project_repository: str,
    project_source_sha: str,
    project_source_ref: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> None:
    _validate_repository(project_repository, "project repository")
    _validate_sha(project_source_sha, "project source SHA")
    if project_source_ref != SOURCE_REF:
        raise ValueError(f"project source ref must be exactly {SOURCE_REF}")
    _validate_integer_string(workflow_run_id, "workflow run id")
    _validate_integer_string(workflow_run_attempt, "workflow run attempt")


def _candidate_api_identity(
    run_metadata_path: Path,
    artifact_metadata_path: Path,
    candidate_run_id: str,
    candidate_run_attempt: str,
    candidate_source_sha: str,
    project_repository: str,
) -> dict[str, object]:
    run, _ = _load_json(run_metadata_path, "candidate run API metadata")
    expected_run = int(candidate_run_id)
    expected_attempt = int(candidate_run_attempt)
    repository = run.get("repository")
    if (
        run.get("id") != expected_run
        or run.get("run_attempt") != expected_attempt
        or run.get("name") != "release-candidate"
        or run.get("path") != ".github/workflows/candidate.yml"
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != "master"
        or run.get("head_sha") != candidate_source_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or type(repository) is not dict
        or repository.get("full_name") != project_repository
    ):
        raise ValueError(
            "candidate run API metadata does not identify one successful exact run"
        )
    artifacts, _ = _load_json(
        artifact_metadata_path, "candidate artifacts API metadata"
    )
    values = artifacts.get("artifacts")
    if type(values) is not list or artifacts.get("total_count") != len(values):
        raise ValueError("candidate artifact API response is incomplete or paginated")
    expected_name = f"release-candidate-dist-attempt-{candidate_run_attempt}"
    matches = [
        value
        for value in values
        if type(value) is dict and value.get("name") == expected_name
    ]
    if len(matches) != 1:
        raise ValueError(
            "candidate artifact name is missing or not unique in the exact run"
        )
    artifact = matches[0]
    artifact_id = _positive_integer(artifact.get("id"), "candidate artifact id")
    artifact_digest = _validate_digest(
        artifact.get("digest"), "candidate artifact API digest"
    )
    artifact_size = _positive_integer(
        artifact.get("size_in_bytes"), "candidate artifact size"
    )
    workflow_run = artifact.get("workflow_run")
    if (
        artifact.get("expired") is not False
        or type(workflow_run) is not dict
        or workflow_run.get("id") != expected_run
        or workflow_run.get("head_branch") != "master"
        or workflow_run.get("head_sha") != candidate_source_sha
    ):
        raise ValueError("candidate artifact is expired or belongs to a different run")
    expected_archive_url = (
        f"https://api.github.com/repos/{project_repository}/actions/artifacts/"
        f"{artifact_id}/zip"
    )
    if artifact.get("archive_download_url") != expected_archive_url:
        raise ValueError("candidate artifact archive URL identity mismatch")
    return {
        "artifact_digest": artifact_digest,
        "artifact_id": artifact_id,
        "artifact_name": expected_name,
        "artifact_size": artifact_size,
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "master",
        "head_sha": candidate_source_sha,
        "path": ".github/workflows/candidate.yml",
        "run_attempt": candidate_run_attempt,
        "run_id": candidate_run_id,
        "workflow_name": "release-candidate",
    }


def build_candidate_binding(
    candidate_dist: Path,
    run_metadata_path: Path,
    artifact_metadata_path: Path,
    candidate_cli_binary: Path,
    candidate_run_id: str,
    candidate_run_attempt: str,
    candidate_manifest_sha256: str,
    candidate_source_sha: str,
    oci_manifest_digest: str,
    project_repository: str,
    project_source_sha: str,
    project_source_ref: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> dict[str, object]:
    """Bind already-verified candidate bytes to this qualification run."""

    _validate_project_identity(
        project_repository,
        project_source_sha,
        project_source_ref,
        workflow_run_id,
        workflow_run_attempt,
    )
    candidate_run_id = _validate_integer_string(candidate_run_id, "candidate run id")
    candidate_run_attempt = _validate_integer_string(
        candidate_run_attempt, "candidate run attempt"
    )
    candidate_source_sha = _validate_sha(candidate_source_sha, "candidate source SHA")
    candidate_manifest_sha256 = _validate_digest(
        candidate_manifest_sha256, "candidate manifest digest"
    )
    oci_manifest_digest = _validate_digest(
        oci_manifest_digest, "candidate OCI manifest digest"
    )
    if candidate_source_sha != project_source_sha:
        raise ValueError(
            "candidate source SHA must equal the exact qualification master SHA"
        )
    api_identity = _candidate_api_identity(
        run_metadata_path,
        artifact_metadata_path,
        candidate_run_id,
        candidate_run_attempt,
        candidate_source_sha,
        project_repository,
    )
    _walk_plain_tree(candidate_dist, "downloaded candidate artifact")
    manifest, manifest_bytes = _load_json(
        candidate_dist / "candidate-manifest.json", "candidate manifest"
    )
    if _file_hash(manifest_bytes) != candidate_manifest_sha256:
        raise ValueError("candidate manifest bytes do not match the required digest")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("kind") != "tomorrowci.release-candidate.v1"
        or manifest.get("status") != "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED"
    ):
        raise ValueError("candidate manifest is not an unauthorized release candidate")
    source = manifest.get("source")
    workflow = manifest.get("workflow")
    if type(source) is not dict or type(workflow) is not dict:
        raise ValueError("candidate manifest source/workflow identity is missing")
    if (
        source.get("repository") != project_repository
        or source.get("commit") != candidate_source_sha
        or source.get("ref") != SOURCE_REF
        or source.get("dirty") is not False
        or workflow.get("run_id") != int(candidate_run_id)
        or workflow.get("run_attempt") != int(candidate_run_attempt)
    ):
        raise ValueError("candidate manifest does not match the required exact run")
    provenance, provenance_bytes = _load_oci_canonical_json(
        candidate_dist / "image-provenance.json", "candidate OCI provenance"
    )
    if (
        provenance.get("schema_version") != 1
        or provenance.get("kind") != "tomorrowci.oci-candidate-provenance.v1"
        or provenance.get("status") != "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED"
    ):
        raise ValueError("candidate OCI provenance identity mismatch")
    provenance_source = provenance.get("source")
    provenance_workflow = provenance.get("workflow")
    oci = provenance.get("oci")
    if (
        type(provenance_source) is not dict
        or type(provenance_workflow) is not dict
        or type(oci) is not dict
        or type(oci.get("manifest")) is not dict
    ):
        raise ValueError("candidate OCI provenance is incomplete")
    if (
        provenance_source.get("repository") != project_repository
        or provenance_source.get("commit") != candidate_source_sha
        or provenance_workflow.get("run_id") != int(candidate_run_id)
        or provenance_workflow.get("run_attempt") != int(candidate_run_attempt)
        or oci["manifest"].get("digest") != oci_manifest_digest
        or provenance.get("version") != manifest.get("version")
    ):
        raise ValueError(
            "candidate OCI provenance does not match the required exact run"
        )
    payload = manifest.get("payload")
    if type(payload) is not list:
        raise ValueError("candidate manifest payload is missing")
    provenance_entries = [
        entry
        for entry in payload
        if type(entry) is dict and entry.get("name") == "image-provenance.json"
    ]
    if (
        len(provenance_entries) != 1
        or provenance_entries[0].get("sha256") != _file_hash(provenance_bytes)
        or provenance_entries[0].get("size") != len(provenance_bytes)
    ):
        raise ValueError("candidate manifest does not bind the exact OCI provenance")
    version = _string(manifest.get("version"), "candidate version")
    cli_archive_name = f"tomorrowci-v{version}-x86_64-unknown-linux-gnu.tar.gz"
    cli_entries = [
        entry
        for entry in payload
        if type(entry) is dict and entry.get("name") == cli_archive_name
    ]
    if len(cli_entries) != 1:
        raise ValueError("candidate manifest has no unique Linux x64 CLI archive")
    cli_archive_data = _snapshot(
        candidate_dist / cli_archive_name, "candidate Linux x64 CLI archive"
    )
    if cli_entries[0].get("sha256") != _file_hash(cli_archive_data) or cli_entries[
        0
    ].get("size") != len(cli_archive_data):
        raise ValueError("candidate manifest does not bind the Linux x64 CLI archive")
    cli_binary_data = _snapshot(candidate_cli_binary, "extracted candidate CLI binary")
    return {
        "candidate": {
            "artifact_digest": api_identity["artifact_digest"],
            "artifact_id": api_identity["artifact_id"],
            "artifact_name": api_identity["artifact_name"],
            "artifact_size": api_identity["artifact_size"],
            "cli_payload": {
                "archive_name": cli_archive_name,
                "archive_sha256": _file_hash(cli_archive_data),
                "archive_size": len(cli_archive_data),
                "binary_sha256": _file_hash(cli_binary_data),
                "binary_size": len(cli_binary_data),
                "target": "x86_64-unknown-linux-gnu",
            },
            "manifest_sha256": candidate_manifest_sha256,
            "oci_manifest_digest": oci_manifest_digest,
            "oci_provenance_sha256": _file_hash(provenance_bytes),
            "run_attempt": candidate_run_attempt,
            "run_id": candidate_run_id,
            "source_sha": candidate_source_sha,
            "version": version,
            "workflow": {
                key: api_identity[key]
                for key in (
                    "conclusion",
                    "event",
                    "head_branch",
                    "head_sha",
                    "path",
                    "workflow_name",
                )
            },
        },
        "kind": BINDING_KIND,
        "qualification": {
            "repository": project_repository,
            "source_ref": project_source_ref,
            "source_sha": project_source_sha,
            "workflow_path": WORKFLOW_PATH,
            "workflow_run_attempt": workflow_run_attempt,
            "workflow_run_id": workflow_run_id,
        },
        "status": BINDING_STATUS,
    }


def verify_candidate_binding(
    path: Path,
    candidate_cli_archive: Path,
    candidate_cli_binary: Path,
    candidate_run_id: str,
    candidate_run_attempt: str,
    candidate_manifest_sha256: str,
    candidate_source_sha: str,
    oci_manifest_digest: str,
    project_repository: str,
    project_source_sha: str,
    project_source_ref: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> tuple[dict[str, object], bytes]:
    _validate_project_identity(
        project_repository,
        project_source_sha,
        project_source_ref,
        workflow_run_id,
        workflow_run_attempt,
    )
    candidate_run_id = _validate_integer_string(candidate_run_id, "candidate run id")
    candidate_run_attempt = _validate_integer_string(
        candidate_run_attempt, "candidate run attempt"
    )
    candidate_manifest_sha256 = _validate_digest(
        candidate_manifest_sha256, "candidate manifest digest"
    )
    candidate_source_sha = _validate_sha(candidate_source_sha, "candidate source SHA")
    oci_manifest_digest = _validate_digest(
        oci_manifest_digest, "candidate OCI manifest digest"
    )
    if candidate_source_sha != project_source_sha:
        raise ValueError(
            "candidate source SHA must equal the exact qualification master SHA"
        )
    binding, data = _load_canonical_json(path, "candidate qualification binding")
    _object(
        binding, {"candidate", "kind", "qualification", "status"}, "candidate binding"
    )
    if binding["kind"] != BINDING_KIND or binding["status"] != BINDING_STATUS:
        raise ValueError("candidate binding kind/status mismatch")
    candidate = _object(
        binding["candidate"],
        {
            "artifact_digest",
            "artifact_id",
            "artifact_name",
            "artifact_size",
            "cli_payload",
            "manifest_sha256",
            "oci_manifest_digest",
            "oci_provenance_sha256",
            "run_attempt",
            "run_id",
            "source_sha",
            "version",
            "workflow",
        },
        "candidate binding candidate",
    )
    expected_candidate = {
        "artifact_name": f"release-candidate-dist-attempt-{candidate_run_attempt}",
        "manifest_sha256": candidate_manifest_sha256,
        "oci_manifest_digest": oci_manifest_digest,
        "run_attempt": candidate_run_attempt,
        "run_id": candidate_run_id,
        "source_sha": candidate_source_sha,
    }
    for key, expected in expected_candidate.items():
        if candidate.get(key) != expected:
            raise ValueError(f"candidate binding {key} mismatch")
    _validate_digest(candidate.get("oci_provenance_sha256"), "OCI provenance digest")
    _string(candidate.get("version"), "candidate version")
    _positive_integer(candidate.get("artifact_id"), "candidate binding artifact id")
    _positive_integer(candidate.get("artifact_size"), "candidate binding artifact size")
    _validate_digest(
        candidate.get("artifact_digest"), "candidate binding artifact digest"
    )
    cli_payload = _object(
        candidate.get("cli_payload"),
        {
            "archive_name",
            "archive_sha256",
            "archive_size",
            "binary_sha256",
            "binary_size",
            "target",
        },
        "candidate binding CLI payload",
    )
    expected_archive_name = (
        f"tomorrowci-v{candidate['version']}-x86_64-unknown-linux-gnu.tar.gz"
    )
    if (
        cli_payload.get("archive_name") != expected_archive_name
        or cli_payload.get("target") != "x86_64-unknown-linux-gnu"
    ):
        raise ValueError("candidate binding CLI archive identity mismatch")
    archive_data = _snapshot(candidate_cli_archive, "candidate binding CLI archive")
    if _validate_digest(
        cli_payload.get("archive_sha256"), "CLI archive digest"
    ) != _file_hash(archive_data) or _positive_integer(
        cli_payload.get("archive_size"), "CLI archive size"
    ) != len(archive_data):
        raise ValueError("candidate CLI archive bytes do not match the binding")
    _validate_digest(cli_payload.get("binary_sha256"), "candidate CLI binary digest")
    binary_data = _snapshot(candidate_cli_binary, "extracted candidate CLI binary")
    if cli_payload["binary_sha256"] != _file_hash(binary_data) or _positive_integer(
        cli_payload.get("binary_size"), "candidate CLI binary size"
    ) != len(binary_data):
        raise ValueError("extracted candidate CLI binary does not match the binding")
    workflow = _object(
        candidate.get("workflow"),
        {"conclusion", "event", "head_branch", "head_sha", "path", "workflow_name"},
        "candidate binding workflow",
    )
    if workflow != {
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "master",
        "head_sha": candidate_source_sha,
        "path": ".github/workflows/candidate.yml",
        "workflow_name": "release-candidate",
    }:
        raise ValueError("candidate binding workflow metadata mismatch")
    qualification = _object(
        binding["qualification"],
        {
            "repository",
            "source_ref",
            "source_sha",
            "workflow_path",
            "workflow_run_attempt",
            "workflow_run_id",
        },
        "candidate binding qualification",
    )
    expected_qualification = {
        "repository": project_repository,
        "source_ref": project_source_ref,
        "source_sha": project_source_sha,
        "workflow_path": WORKFLOW_PATH,
        "workflow_run_attempt": workflow_run_attempt,
        "workflow_run_id": workflow_run_id,
    }
    if qualification != expected_qualification:
        raise ValueError("candidate binding qualification identity mismatch")
    return binding, data


def _candidate_binding_identity(
    binding: dict[str, object], binding_bytes: bytes
) -> dict[str, object]:
    candidate = binding["candidate"]
    return {
        "artifact_digest": candidate["artifact_digest"],
        "artifact_id": candidate["artifact_id"],
        "artifact_size": candidate["artifact_size"],
        "cli_archive_sha256": candidate["cli_payload"]["archive_sha256"],
        "cli_binary_sha256": candidate["cli_payload"]["binary_sha256"],
        "candidate_manifest_sha256": candidate["manifest_sha256"],
        "candidate_run_attempt": candidate["run_attempt"],
        "candidate_run_id": candidate["run_id"],
        "candidate_source_sha": candidate["source_sha"],
        "oci_manifest_digest": candidate["oci_manifest_digest"],
        "record_sha256": _file_hash(binding_bytes),
    }


def build_record(
    verified: VerifiedRun,
    context: FrozenTarget,
    candidate_binding: dict[str, object],
    candidate_binding_bytes: bytes,
    project_repository: str,
    project_source_sha: str,
    project_source_ref: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> dict[str, object]:
    _validate_project_identity(
        project_repository,
        project_source_sha,
        project_source_ref,
        workflow_run_id,
        workflow_run_attempt,
    )
    artifact_name = expected_artifact_name(
        verified.target_id, verified.engine, workflow_run_attempt, project_source_sha
    )
    source = context.target["source"]
    replay_reports = [
        {
            "attempt": report["attempt"],
            "exit_match": report["exit_match"],
            "result_sha256": _file_hash(canonical_json_bytes(report)),
            "signature_match": report["signature_match"],
        }
        for report in verified.replay
    ]
    return {
        "artifact_name": artifact_name,
        "candidate_binding": _candidate_binding_identity(
            candidate_binding, candidate_binding_bytes
        ),
        "config": {
            "normalized_sha256": verified.config_hash,
            "path": context.config_path,
            "source_sha256": context.config_sha256,
        },
        "engine": {"name": verified.engine, "version": verified.engine_version},
        "evidence": {
            "checksums_sha256": verified.checksums_sha256,
            "format": "current_v2",
            "remote_source_sha256": verified.remote_source_sha256,
            "run_id": verified.run_id,
            "run_manifest_sha256": verified.run_sha256,
            "run_path": f".tomorrowci/runs/{verified.run_id}",
        },
        "frontier": {
            "classification": verified.result_class,
            "first_failing_scenario": verified.frontier["first_failing_scenario"],
            "grade": verified.frontier["grade"],
            "horizon_label": verified.frontier["horizon_label"],
            "observed": verified.frontier["observed"],
        },
        "kind": RECORD_KIND,
        "preregistration": {
            "sha256": context.preregistration_sha256,
            "status": context.document["status"],
        },
        "project": {
            "repository": project_repository,
            "source_ref": project_source_ref,
            "source_sha": project_source_sha,
            "workflow_path": WORKFLOW_PATH,
            "workflow_run_attempt": workflow_run_attempt,
            "workflow_run_id": workflow_run_id,
        },
        "remote_source": {
            "commit": source["commit"],
            "repository": source["repository"],
            "url": source["url"],
        },
        "replay": {
            "attempts": replay_reports,
            "count": len(replay_reports),
            "scenario_id": verified.replay_scenario,
        },
        "results": list(verified.results),
        "status": STATUS,
        "target_id": verified.target_id,
    }


def _write_new_canonical(path: Path, value: object, label: str) -> None:
    parent = path.parent
    _plain_directory(parent, f"{label} parent")
    if path.exists() or path.is_symlink():
        raise ValueError(f"refusing to overwrite existing {label}: {path}")
    try:
        with path.open("xb") as handle:
            handle.write(canonical_json_bytes(value))
    except OSError as error:
        raise ValueError(f"could not create {label}: {error}") from error


def verify_artifact(
    artifact_root: Path,
    candidate_binding_path: Path,
    candidate_cli_archive: Path,
    candidate_cli_binary: Path,
    candidate_run_id: str,
    candidate_run_attempt: str,
    candidate_manifest_sha256: str,
    candidate_source_sha: str,
    oci_manifest_digest: str,
    preregistration_path: Path,
    repository_root: Path,
    project_repository: str,
    project_source_sha: str,
    project_source_ref: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> dict[str, object]:
    _validate_project_identity(
        project_repository,
        project_source_sha,
        project_source_ref,
        workflow_run_id,
        workflow_run_attempt,
    )
    _walk_plain_tree(artifact_root, "downloaded qualification artifact")
    candidate_binding, candidate_binding_bytes = verify_candidate_binding(
        candidate_binding_path,
        candidate_cli_archive,
        candidate_cli_binary,
        candidate_run_id,
        candidate_run_attempt,
        candidate_manifest_sha256,
        candidate_source_sha,
        oci_manifest_digest,
        project_repository,
        project_source_sha,
        project_source_ref,
        workflow_run_id,
        workflow_run_attempt,
    )
    entries = {entry.name for entry in artifact_root.iterdir()}
    if entries != {".tomorrowci", "qualification-record.json"}:
        raise ValueError(
            "qualification artifact root must contain exactly .tomorrowci and qualification-record.json"
        )
    record, record_bytes = _load_canonical_json(
        artifact_root / "qualification-record.json", "qualification record"
    )
    if record.get("kind") != RECORD_KIND or record.get("status") != STATUS:
        raise ValueError("qualification record kind/status mismatch")
    target_id = _string(record.get("target_id"), "record target id")
    engine_object = record.get("engine")
    if type(engine_object) is not dict:
        raise ValueError("qualification record engine is missing")
    engine = _string(engine_object.get("name"), "record engine name")
    engine_version = _string(engine_object.get("version"), "record engine version")
    expected_name = expected_artifact_name(
        target_id, engine, workflow_run_attempt, project_source_sha
    )
    if (
        artifact_root.name != expected_name
        or record.get("artifact_name") != expected_name
    ):
        raise ValueError("qualification artifact name/path identity mismatch")
    runs_root = artifact_root / ".tomorrowci" / "runs"
    _plain_directory(runs_root, "artifact run root")
    run_entries = list(runs_root.iterdir())
    if len(run_entries) != 1:
        raise ValueError("qualification artifact must contain exactly one run")
    run_root = run_entries[0]
    _plain_directory(run_root, "artifact run")
    verified, context = validate_run(
        run_root,
        preregistration_path,
        repository_root,
        target_id,
        engine,
        engine_version,
        required_replays=2,
        expected_tool_version=candidate_binding["candidate"]["version"],
    )
    expected_record = build_record(
        verified,
        context,
        candidate_binding,
        candidate_binding_bytes,
        project_repository,
        project_source_sha,
        project_source_ref,
        workflow_run_id,
        workflow_run_attempt,
    )
    if record_bytes != canonical_json_bytes(expected_record):
        raise ValueError(
            "qualification record does not exactly match verified evidence"
        )
    _walk_plain_tree(
        artifact_root, "downloaded qualification artifact after validation"
    )
    return record


def build_summary(
    artifacts_root: Path,
    candidate_binding_path: Path,
    candidate_cli_archive: Path,
    candidate_cli_binary: Path,
    candidate_run_id: str,
    candidate_run_attempt: str,
    candidate_manifest_sha256: str,
    candidate_source_sha: str,
    oci_manifest_digest: str,
    preregistration_path: Path,
    repository_root: Path,
    project_repository: str,
    project_source_sha: str,
    project_source_ref: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> dict[str, object]:
    _plain_directory(artifacts_root, "downloaded artifact collection")
    entries = sorted(artifacts_root.iterdir(), key=lambda path: path.name)
    if any(not entry.is_dir() or entry.is_symlink() for entry in entries):
        raise ValueError(
            "downloaded artifact collection may contain only plain directories"
        )
    prereg = preregistration_contract.verify_preregistration(
        preregistration_path, repository_root
    )
    candidate_binding, candidate_binding_bytes = verify_candidate_binding(
        candidate_binding_path,
        candidate_cli_archive,
        candidate_cli_binary,
        candidate_run_id,
        candidate_run_attempt,
        candidate_manifest_sha256,
        candidate_source_sha,
        oci_manifest_digest,
        project_repository,
        project_source_sha,
        project_source_ref,
        workflow_run_id,
        workflow_run_attempt,
    )
    expected_pairs = {
        (target_id, engine) for target_id in prereg.target_ids for engine in ENGINES
    }
    if len(entries) != len(expected_pairs):
        raise ValueError(
            f"read-back requires exactly {len(expected_pairs)} isolated artifacts, got {len(entries)}"
        )
    records = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        record = verify_artifact(
            entry,
            candidate_binding_path,
            candidate_cli_archive,
            candidate_cli_binary,
            candidate_run_id,
            candidate_run_attempt,
            candidate_manifest_sha256,
            candidate_source_sha,
            oci_manifest_digest,
            preregistration_path,
            repository_root,
            project_repository,
            project_source_sha,
            project_source_ref,
            workflow_run_id,
            workflow_run_attempt,
        )
        pair = (record["target_id"], record["engine"]["name"])
        if pair in seen:
            raise ValueError(f"duplicate qualification artifact for {pair!r}")
        seen.add(pair)
        records.append(
            {
                "artifact_name": record["artifact_name"],
                "config_sha256": record["config"]["source_sha256"],
                "engine": record["engine"],
                "frontier": record["frontier"],
                "record_sha256": _file_hash(canonical_json_bytes(record)),
                "remote_source": record["remote_source"],
                "replay_count": record["replay"]["count"],
                "run_id": record["evidence"]["run_id"],
                "target_id": record["target_id"],
            }
        )
    if seen != expected_pairs:
        missing = sorted(expected_pairs - seen)
        extra = sorted(seen - expected_pairs)
        raise ValueError(
            f"qualification matrix mismatch: missing={missing!r} extra={extra!r}"
        )
    records.sort(key=lambda value: (value["target_id"], value["engine"]["name"]))
    return {
        "artifact_count": len(records),
        "candidate_binding": _candidate_binding_identity(
            candidate_binding, candidate_binding_bytes
        ),
        "kind": SUMMARY_KIND,
        "matrix": records,
        "preregistration": {"sha256": prereg.sha256, "status": "NOT_RUN"},
        "project": {
            "repository": project_repository,
            "source_ref": project_source_ref,
            "source_sha": project_source_sha,
            "workflow_path": WORKFLOW_PATH,
            "workflow_run_attempt": workflow_run_attempt,
            "workflow_run_id": workflow_run_id,
        },
        "status": STATUS,
    }


def _common_context(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--preregistration", type=Path, default=DEFAULT_PREREGISTRATION)
    parser.add_argument("--repository-root", type=Path, default=ROOT)


def _run_context(parser: argparse.ArgumentParser) -> None:
    _common_context(parser)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--engine", choices=ENGINES, required=True)
    parser.add_argument("--engine-version", required=True)


def _project_context(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-repository", required=True)
    parser.add_argument("--project-source-sha", required=True)
    parser.add_argument("--project-source-ref", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)


def _candidate_context(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--candidate-binding", type=Path, required=True)
    parser.add_argument("--candidate-cli-archive", type=Path, required=True)
    parser.add_argument("--candidate-cli-binary", type=Path, required=True)
    parser.add_argument("--candidate-run-id", required=True)
    parser.add_argument("--candidate-run-attempt", required=True)
    parser.add_argument("--candidate-manifest-sha256", required=True)
    parser.add_argument("--candidate-source-sha", required=True)
    parser.add_argument("--oci-manifest-digest", required=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Validate repository-owned external-target qualification evidence"
    )
    commands = root.add_subparsers(dest="command", required=True)

    inspect_api = commands.add_parser("inspect-candidate-api")
    inspect_api.add_argument("--run-metadata", type=Path, required=True)
    inspect_api.add_argument("--artifact-metadata", type=Path, required=True)
    inspect_api.add_argument("--candidate-run-id", required=True)
    inspect_api.add_argument("--candidate-run-attempt", required=True)
    inspect_api.add_argument("--candidate-source-sha", required=True)
    inspect_api.add_argument("--project-repository", required=True)

    create_binding = commands.add_parser("create-binding")
    _project_context(create_binding)
    create_binding.add_argument("--candidate-dist", type=Path, required=True)
    create_binding.add_argument("--run-metadata", type=Path, required=True)
    create_binding.add_argument("--artifact-metadata", type=Path, required=True)
    create_binding.add_argument("--candidate-cli-binary", type=Path, required=True)
    create_binding.add_argument("--candidate-run-id", required=True)
    create_binding.add_argument("--candidate-run-attempt", required=True)
    create_binding.add_argument("--candidate-manifest-sha256", required=True)
    create_binding.add_argument("--candidate-source-sha", required=True)
    create_binding.add_argument("--oci-manifest-digest", required=True)
    create_binding.add_argument("--output", type=Path, required=True)

    verify_binding = commands.add_parser("verify-binding")
    _project_context(verify_binding)
    _candidate_context(verify_binding)

    select = commands.add_parser("select-replay")
    _run_context(select)
    select.add_argument("--expected-tool-version", required=True)

    create = commands.add_parser("create-record")
    _run_context(create)
    _project_context(create)
    _candidate_context(create)
    create.add_argument("--output", type=Path, required=True)

    verify = commands.add_parser("verify-artifact")
    _common_context(verify)
    _project_context(verify)
    _candidate_context(verify)
    verify.add_argument("--artifact-root", type=Path, required=True)

    summarize = commands.add_parser("summarize")
    _common_context(summarize)
    _project_context(summarize)
    _candidate_context(summarize)
    summarize.add_argument("--artifacts-root", type=Path, required=True)
    summarize.add_argument("--output", type=Path, required=True)

    verify_summary = commands.add_parser("verify-summary")
    _common_context(verify_summary)
    _project_context(verify_summary)
    _candidate_context(verify_summary)
    verify_summary.add_argument("--artifacts-root", type=Path, required=True)
    verify_summary.add_argument("--summary", type=Path, required=True)
    return root


def _run_main(args: argparse.Namespace) -> None:
    if args.command == "inspect-candidate-api":
        candidate_run_id = _validate_integer_string(
            args.candidate_run_id, "candidate run id"
        )
        candidate_run_attempt = _validate_integer_string(
            args.candidate_run_attempt, "candidate run attempt"
        )
        candidate_source_sha = _validate_sha(
            args.candidate_source_sha, "candidate source SHA"
        )
        project_repository = _validate_repository(
            args.project_repository, "project repository"
        )
        identity = _candidate_api_identity(
            args.run_metadata,
            args.artifact_metadata,
            candidate_run_id,
            candidate_run_attempt,
            candidate_source_sha,
            project_repository,
        )
        print("candidate API metadata: PASS")
        print(f"artifact_id: {identity['artifact_id']}")
        print(f"artifact_digest: {identity['artifact_digest']}")
        print(f"artifact_size: {identity['artifact_size']}")
        return

    if args.command == "create-binding":
        binding = build_candidate_binding(
            args.candidate_dist,
            args.run_metadata,
            args.artifact_metadata,
            args.candidate_cli_binary,
            args.candidate_run_id,
            args.candidate_run_attempt,
            args.candidate_manifest_sha256,
            args.candidate_source_sha,
            args.oci_manifest_digest,
            args.project_repository,
            args.project_source_sha,
            args.project_source_ref,
            args.workflow_run_id,
            args.workflow_run_attempt,
        )
        _write_new_canonical(args.output, binding, "candidate qualification binding")
        print(f"candidate qualification binding: PASS: {args.output}")
        return

    if args.command == "verify-binding":
        binding, _ = verify_candidate_binding(
            args.candidate_binding,
            args.candidate_cli_archive,
            args.candidate_cli_binary,
            args.candidate_run_id,
            args.candidate_run_attempt,
            args.candidate_manifest_sha256,
            args.candidate_source_sha,
            args.oci_manifest_digest,
            args.project_repository,
            args.project_source_sha,
            args.project_source_ref,
            args.workflow_run_id,
            args.workflow_run_attempt,
        )
        print("candidate qualification binding: PASS")
        print(f"candidate_version: {binding['candidate']['version']}")
        print(
            "candidate_cli_archive: "
            f"{binding['candidate']['cli_payload']['archive_name']}"
        )
        print(
            "candidate_cli_binary_sha256: "
            f"{binding['candidate']['cli_payload']['binary_sha256']}"
        )
        print(
            "candidate_cli_binary_size: "
            f"{binding['candidate']['cli_payload']['binary_size']}"
        )
        return

    if args.command == "select-replay":
        verified, _ = validate_run(
            args.run_root,
            args.preregistration,
            args.repository_root,
            args.target_id,
            args.engine,
            args.engine_version,
            required_replays=0,
            expected_tool_version=args.expected_tool_version,
        )
        print(verified.replay_scenario)
        return

    if args.command == "create-record":
        candidate_binding, candidate_binding_bytes = verify_candidate_binding(
            args.candidate_binding,
            args.candidate_cli_archive,
            args.candidate_cli_binary,
            args.candidate_run_id,
            args.candidate_run_attempt,
            args.candidate_manifest_sha256,
            args.candidate_source_sha,
            args.oci_manifest_digest,
            args.project_repository,
            args.project_source_sha,
            args.project_source_ref,
            args.workflow_run_id,
            args.workflow_run_attempt,
        )
        verified, context = validate_run(
            args.run_root,
            args.preregistration,
            args.repository_root,
            args.target_id,
            args.engine,
            args.engine_version,
            required_replays=2,
            expected_tool_version=candidate_binding["candidate"]["version"],
        )
        record = build_record(
            verified,
            context,
            candidate_binding,
            candidate_binding_bytes,
            args.project_repository,
            args.project_source_sha,
            args.project_source_ref,
            args.workflow_run_id,
            args.workflow_run_attempt,
        )
        _write_new_canonical(args.output, record, "qualification record")
        print(f"qualification record: PASS: {args.output}")
        return

    if args.command == "verify-artifact":
        record = verify_artifact(
            args.artifact_root,
            args.candidate_binding,
            args.candidate_cli_archive,
            args.candidate_cli_binary,
            args.candidate_run_id,
            args.candidate_run_attempt,
            args.candidate_manifest_sha256,
            args.candidate_source_sha,
            args.oci_manifest_digest,
            args.preregistration,
            args.repository_root,
            args.project_repository,
            args.project_source_sha,
            args.project_source_ref,
            args.workflow_run_id,
            args.workflow_run_attempt,
        )
        print(
            "qualification artifact: PASS: "
            f"{record['target_id']}/{record['engine']['name']}"
        )
        return

    summary = build_summary(
        args.artifacts_root,
        args.candidate_binding,
        args.candidate_cli_archive,
        args.candidate_cli_binary,
        args.candidate_run_id,
        args.candidate_run_attempt,
        args.candidate_manifest_sha256,
        args.candidate_source_sha,
        args.oci_manifest_digest,
        args.preregistration,
        args.repository_root,
        args.project_repository,
        args.project_source_sha,
        args.project_source_ref,
        args.workflow_run_id,
        args.workflow_run_attempt,
    )
    if args.command == "summarize":
        _write_new_canonical(args.output, summary, "qualification summary")
        print(f"qualification summary: PASS: {args.output}")
        return
    actual, data = _load_canonical_json(args.summary, "qualification summary")
    if data != canonical_json_bytes(summary) or actual != summary:
        raise ValueError(
            "qualification summary does not match exact downloaded artifacts"
        )
    print("qualification summary: PASS")


def main(argv: list[str] | None = None) -> int:
    try:
        _run_main(parser().parse_args(argv))
    except (OSError, ValueError, KeyError) as error:
        print(f"external qualification evidence: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
