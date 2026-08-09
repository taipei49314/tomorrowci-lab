//! Typed domain models. Verdict engine consumes these — not ad-hoc terminal strings.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Python,
    Node,
    Rust,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentAxis {
    Runtime,
    Dependencies,
    PackageManager,
    BaseImage,
    Os,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceGrade {
    Observed,
    Simulated,
    ScheduledRisk,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    BaselinePass,
    BaselineInvalid,
    FuturePass,
    FutureFail,
    Flaky,
    Blocked,
    Unsupported,
    Inconclusive,
}

impl Verdict {
    pub fn is_pass_like(self) -> bool {
        matches!(self, Self::BaselinePass | Self::FuturePass)
    }

    /// BLOCKED / UNSUPPORTED / INCONCLUSIVE must never become PASS.
    pub fn may_not_be_promoted_to_pass(self) -> bool {
        matches!(
            self,
            Self::Blocked
                | Self::Unsupported
                | Self::Inconclusive
                | Self::BaselineInvalid
                | Self::Flaky
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySnapshot {
    pub source: String,
    pub path: PathBuf,
    pub commit_sha: Option<String>,
    pub is_disposable_copy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectDetection {
    pub ecosystem: Ecosystem,
    pub manifests: Vec<String>,
    pub package_manager: String,
    pub confidence: f64,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub runtime: String,
    pub dependencies: String,
    pub declared_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub axis: EnvironmentAxis,
    pub label: String,
    pub version: String,
    pub channel: String,
    pub grade_if_executed: EvidenceGrade,
    pub order_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub is_baseline: bool,
    pub runtime: String,
    pub dependencies: String,
    pub axes_changed: Vec<EnvironmentAxis>,
    pub candidates: Vec<String>,
    pub grade: EvidenceGrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub network: bool,
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentSpec {
    /// Human-readable image tag (never overwritten by digest).
    #[serde(default)]
    pub image_tag: String,
    /// Legacy alias of `image_tag` for older evidence/readers.
    pub image: String,
    /// Immutable digest ref (`repo@sha256:...` or `sha256:...`).
    pub image_digest: Option<String>,
    pub workdir: String,
    pub env: IndexMap<String, String>,
    pub network_mode: String,
    pub memory_mb: u32,
    pub cpus: f32,
    pub pids_limit: u32,
    pub user: Option<String>,
    pub read_only_root: bool,
    /// Mounted scenario-local state root inside the container (e.g. `/work/.tomorrowci/scenarios/id`).
    #[serde(default)]
    pub scenario_state_root: Option<String>,
    #[serde(default)]
    pub fetch_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub test_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(default)]
    pub engine_version: Option<String>,
}

impl EnvironmentSpec {
    /// Prefer explicit image_tag; fall back to legacy `image`.
    pub fn tag(&self) -> &str {
        if !self.image_tag.is_empty() {
            &self.image_tag
        } else {
            &self.image
        }
    }

    /// Docker/Podman image reference: digest if present, else tag.
    pub fn run_image_ref(&self) -> String {
        self.image_digest
            .clone()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| self.tag().to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunIdentity {
    pub source_commit: Option<String>,
    /// `None` means Git status could not be established (including non-Git input).
    /// Unknown must never be serialized as a falsely clean tree.
    #[serde(default)]
    pub dirty_tree: Option<bool>,
    pub tool_version: String,
    pub adapter_name: String,
    pub adapter_version: String,
    pub config_hash: String,
    pub manifest_hashes: IndexMap<String, String>,
    pub container_engine: Option<String>,
    pub container_engine_version: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// Validate the immutable image identity accepted in current evidence.
///
/// The canonical forms are either `sha256:<64 lowercase hex>` or an OCI-style
/// repository name followed by `@` and that exact digest. Repository digests
/// never carry a mutable tag.
pub fn validate_image_digest(raw: &str) -> std::result::Result<(), String> {
    let (name, digest) = match raw.split_once('@') {
        Some((name, digest)) => {
            if name.is_empty() || digest.contains('@') {
                return Err(format!("invalid canonical image digest: {raw:?}"));
            }
            validate_image_repository_name(name)?;
            (Some(name), digest)
        }
        None => (None, raw),
    };

    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(format!(
            "image digest must use sha256:<64 lowercase hex>: {raw:?}"
        ));
    };
    if hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || hex.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!(
            "image digest must contain exactly 64 lowercase hexadecimal characters: {raw:?}"
        ));
    }
    let _ = name;
    Ok(())
}

/// Return the exact algorithm-and-hash portion after canonical validation.
pub fn canonical_image_digest_value(raw: &str) -> std::result::Result<&str, String> {
    validate_image_digest(raw)?;
    Ok(raw
        .rsplit_once('@')
        .map(|(_, digest)| digest)
        .unwrap_or(raw))
}

fn validate_image_repository_name(name: &str) -> std::result::Result<(), String> {
    if name.len() > 255
        || name.starts_with('/')
        || name.ends_with('/')
        || name.contains("//")
        || !name.is_ascii()
        || name.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!("noncanonical image repository name: {name:?}"));
    }

    for (index, component) in name.split('/').enumerate() {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!("noncanonical image repository name: {name:?}"));
        }
        let repository_component = if index == 0 {
            if let Some((host, port)) = component.rsplit_once(':') {
                if host.is_empty()
                    || port.is_empty()
                    || !port.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(format!("noncanonical image repository name: {name:?}"));
                }
                host
            } else {
                component
            }
        } else {
            if component.contains(':') {
                return Err(format!(
                    "repository digest must not include a mutable tag: {name:?}"
                ));
            }
            component
        };
        if repository_component.is_empty()
            || !repository_component.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
            || !repository_component
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !repository_component
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(format!("noncanonical image repository name: {name:?}"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub plan_id: String,
    pub scenarios: Vec<Scenario>,
    pub selection_notes: Vec<String>,
    pub budget_max: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawExecutionResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub network_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureSignature {
    pub kind: String,
    pub summary: String,
    pub normalized_hash: String,
    pub primary_frame: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub scenario_id: String,
    pub attempt: u32,
    pub verdict: Verdict,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub failure: Option<FailureSignature>,
    pub environment: EnvironmentSpec,
    pub commands: Vec<CommandSpec>,
}

/// A classification input captured immediately after one test execution.
/// Current evidence derives its verdict from this append-only semantic summary
/// instead of trusting mirrored verdict files alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAttemptRecord {
    pub attempt: u32,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub failure: Option<FailureSignature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestExecutionStatus {
    Completed,
    NotRun,
    ExecutionError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAttemptsSummary {
    pub scenario_id: String,
    pub status: TestExecutionStatus,
    pub attempts: Vec<TestAttemptRecord>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub run_id: String,
    pub scenario_id: Option<String>,
    pub path: String,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakageFrontier {
    pub observed: bool,
    pub horizon_label: Option<String>,
    pub first_failing_scenario: Option<String>,
    pub last_passing_scenario: Option<String>,
    pub changed_axes: Vec<EnvironmentAxis>,
    pub failure_signature: Option<FailureSignature>,
    pub grade: EvidenceGrade,
    pub replay_command: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    /// Evidence semantic schema. Schema 2 is the strict, recursively bound
    /// format; missing/zero denotes pre-schema evidence requiring migration.
    #[serde(default)]
    pub evidence_schema_version: u32,
    pub run_id: String,
    pub tool_version: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub repository: RepositorySnapshot,
    pub config_hash: String,
    pub detection: ProjectDetection,
    pub baseline: Baseline,
    pub plan: ExecutionPlan,
    pub results: Vec<ExecutionResult>,
    pub frontier: BreakageFrontier,
    pub evidence_root: PathBuf,
    #[serde(default)]
    pub identity: Option<RunIdentity>,
}
