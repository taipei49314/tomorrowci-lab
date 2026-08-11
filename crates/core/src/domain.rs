//! Typed domain models. Verdict engine consumes these — not ad-hoc terminal strings.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

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

/// Provenance for a bounded remote source materialization. This record is
/// optional for local scans, but current evidence that contains it must bind
/// the immutable request to the captured workspace manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSourceRecord {
    pub schema_version: u32,
    pub requested_url: String,
    pub canonical_origin: String,
    pub requested_commit: String,
    pub resolved_commit: String,
    pub clean_tree: bool,
    pub moving_ref_allowed: bool,
    pub redirects_allowed: bool,
    pub credentials_allowed: bool,
    pub submodules_allowed: bool,
    pub lfs_allowed: bool,
    pub clone_timeout_seconds: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_clone_disk_bytes: u64,
    pub snapshot_file_count: u64,
    pub snapshot_total_bytes: u64,
    pub workspace_manifest_sha256: String,
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

/// A canonical content identity. Current dependency evidence only accepts
/// lowercase SHA-256 so manifests cannot silently substitute a mutable label.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentHash(String);

impl ContentHash {
    pub fn sha256(hex: impl AsRef<str>) -> std::result::Result<Self, String> {
        Self::try_from(format!("sha256:{}", hex.as_ref()))
    }

    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(crate::sha256_bytes(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn hex(&self) -> &str {
        self.0
            .strip_prefix("sha256:")
            .expect("ContentHash construction enforces a sha256 prefix")
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for ContentHash {
    type Error = String;

    fn try_from(raw: String) -> std::result::Result<Self, Self::Error> {
        let Some(hex) = raw.strip_prefix("sha256:") else {
            return Err(format!(
                "content hash must use sha256:<64 lowercase hex>: {raw:?}"
            ));
        };
        if hex.len() != 64
            || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            || hex.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(format!(
                "content hash must contain exactly 64 lowercase hexadecimal characters: {raw:?}"
            ));
        }
        Ok(Self(raw))
    }
}

impl TryFrom<&str> for ContentHash {
    type Error = String;

    fn try_from(raw: &str) -> std::result::Result<Self, Self::Error> {
        Self::try_from(raw.to_owned())
    }
}

impl From<ContentHash> for String {
    fn from(hash: ContentHash) -> Self {
        hash.0
    }
}

/// Defines what exact bytes a dependency content hash covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencySourceKind {
    /// SHA-256 over the canonical `path NUL file-sha256 LF` stream of a
    /// workspace-relative vendored directory, sorted by relative path.
    VendoredTreeSha256V1,
}

/// One exact dependency artifact selected by a package-manager resolution.
/// `source` is a workspace-relative, content-addressed fixture/archive path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDependency {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_kind: DependencySourceKind,
    pub content_sha256: ContentHash,
}

impl ResolvedDependency {
    pub fn validate(&self) -> std::result::Result<(), String> {
        for (field, value) in [
            ("id", self.id.as_str()),
            ("name", self.name.as_str()),
            ("version", self.version.as_str()),
            ("source", self.source.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("resolved dependency {field} must not be empty"));
            }
        }
        validate_workspace_relative_source(&self.source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyChangeKind {
    Add,
    Update,
    Remove,
}

/// A concrete transition between two exact dependency resolutions. Expected
/// necessity belongs to fixture assertions and is intentionally absent here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyChange {
    pub id: String,
    pub name: String,
    pub kind: DependencyChangeKind,
    pub before: Option<ResolvedDependency>,
    pub after: Option<ResolvedDependency>,
}

impl DependencyChange {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.id.trim().is_empty() || self.name.trim().is_empty() {
            return Err("dependency change id and name must not be empty".into());
        }
        let expected_presence = match self.kind {
            DependencyChangeKind::Add => (false, true),
            DependencyChangeKind::Update => (true, true),
            DependencyChangeKind::Remove => (true, false),
        };
        if (self.before.is_some(), self.after.is_some()) != expected_presence {
            return Err(format!(
                "dependency change {} has before/after values inconsistent with {:?}",
                self.id, self.kind
            ));
        }
        for dependency in self.before.iter().chain(self.after.iter()) {
            dependency.validate()?;
            if dependency.name != self.name {
                return Err(format!(
                    "dependency change {} names {}, but resolution names {}",
                    self.id, self.name, dependency.name
                ));
            }
        }
        if matches!(self.kind, DependencyChangeKind::Update) && self.before == self.after {
            return Err(format!(
                "dependency change {} update must alter the exact resolution",
                self.id
            ));
        }
        Ok(())
    }

    pub fn stable_identity(&self) -> std::result::Result<ContentHash, serde_json::Error> {
        let hash = crate::canonical_json_hash(self)?;
        Ok(ContentHash::try_from(hash)
            .expect("canonical_json_hash always returns canonical SHA-256"))
    }
}

/// An exact lock/resolution snapshot. The declared `set_id` is a readable
/// handle; cryptographic identity is recomputed from the remaining fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDependencySet {
    pub set_id: String,
    pub ecosystem: Ecosystem,
    pub package_manager: String,
    pub manifest_sha256: ContentHash,
    pub dependencies: Vec<ResolvedDependency>,
}

impl ResolvedDependencySet {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.set_id.trim().is_empty() || self.package_manager.trim().is_empty() {
            return Err("dependency set id and package manager must not be empty".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for dependency in &self.dependencies {
            dependency.validate()?;
            if !ids.insert(dependency.id.as_str()) {
                return Err(format!(
                    "dependency set {} repeats dependency id {}",
                    self.set_id, dependency.id
                ));
            }
            if !names.insert(dependency.name.as_str()) {
                return Err(format!(
                    "dependency set {} repeats dependency name {}",
                    self.set_id, dependency.name
                ));
            }
        }
        let expected = self
            .expected_manifest_sha256()
            .map_err(|error| format!("cannot hash dependency set {}: {error}", self.set_id))?;
        if self.manifest_sha256 != expected {
            return Err(format!(
                "dependency set {} manifest hash mismatch: declared {}, expected {}",
                self.set_id, self.manifest_sha256, expected
            ));
        }
        Ok(())
    }

    /// Recompute the exact manifest identity without self-referential fields.
    /// Dependency order and the readable `set_id` do not affect the result.
    pub fn expected_manifest_sha256(&self) -> std::result::Result<ContentHash, serde_json::Error> {
        #[derive(Serialize)]
        struct ManifestIdentity<'a> {
            ecosystem: Ecosystem,
            package_manager: &'a str,
            dependencies: Vec<&'a ResolvedDependency>,
        }

        let mut dependencies: Vec<_> = self.dependencies.iter().collect();
        dependencies.sort_by(|left, right| left.id.cmp(&right.id));
        let identity = ManifestIdentity {
            ecosystem: self.ecosystem,
            package_manager: &self.package_manager,
            dependencies,
        };
        let hash = crate::canonical_json_hash(&identity)?;
        Ok(ContentHash::try_from(hash)
            .expect("canonical_json_hash always returns canonical SHA-256"))
    }

    pub fn stable_identity(&self) -> std::result::Result<ContentHash, serde_json::Error> {
        let mut normalized = self.clone();
        normalized.set_id.clear();
        normalized
            .dependencies
            .sort_by(|left, right| left.id.cmp(&right.id));
        let hash = crate::canonical_json_hash(&normalized)?;
        Ok(ContentHash::try_from(hash)
            .expect("canonical_json_hash always returns canonical SHA-256"))
    }
}

/// Baseline and candidate dependency sets plus the concrete transition tested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyCandidateSet {
    pub set_id: String,
    pub baseline: ResolvedDependencySet,
    pub candidate: ResolvedDependencySet,
    pub changes: Vec<DependencyChange>,
}

impl DependencyCandidateSet {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.set_id.trim().is_empty() {
            return Err("dependency candidate set id must not be empty".into());
        }
        self.baseline.validate()?;
        self.candidate.validate()?;
        if self.baseline.ecosystem != self.candidate.ecosystem {
            return Err("baseline and candidate dependency ecosystems must match".into());
        }
        if self.baseline.package_manager != self.candidate.package_manager {
            return Err("baseline and candidate dependency package managers must match".into());
        }
        if self.changes.is_empty() {
            return Err("dependency candidate set must contain a concrete change".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for change in &self.changes {
            change.validate()?;
            if !ids.insert(change.id.as_str()) {
                return Err(format!(
                    "dependency candidate set {} repeats change id {}",
                    self.set_id, change.id
                ));
            }
            if !names.insert(change.name.as_str()) {
                return Err(format!(
                    "dependency candidate set {} repeats change for {}",
                    self.set_id, change.name
                ));
            }
        }

        let baseline_by_name: std::collections::BTreeMap<_, _> = self
            .baseline
            .dependencies
            .iter()
            .map(|dependency| (dependency.name.as_str(), dependency))
            .collect();
        let candidate_by_name: std::collections::BTreeMap<_, _> = self
            .candidate
            .dependencies
            .iter()
            .map(|dependency| (dependency.name.as_str(), dependency))
            .collect();
        let changes_by_name: std::collections::BTreeMap<_, _> = self
            .changes
            .iter()
            .map(|change| (change.name.as_str(), change))
            .collect();
        let dependency_names: std::collections::BTreeSet<_> = baseline_by_name
            .keys()
            .chain(candidate_by_name.keys())
            .copied()
            .collect();
        for name in dependency_names {
            let before = baseline_by_name.get(name).copied();
            let after = candidate_by_name.get(name).copied();
            let declared = changes_by_name.get(name).copied();
            if before == after {
                if declared.is_some() {
                    return Err(format!(
                        "dependency candidate set {} declares unchanged dependency {name}",
                        self.set_id
                    ));
                }
                continue;
            }
            let Some(change) = declared else {
                return Err(format!(
                    "dependency candidate set {} omits concrete change for {name}",
                    self.set_id
                ));
            };
            if change.before.as_ref() != before || change.after.as_ref() != after {
                return Err(format!(
                    "dependency candidate set {} change {} does not match exact baseline/candidate members",
                    self.set_id, change.id
                ));
            }
        }
        for name in changes_by_name.keys() {
            if !baseline_by_name.contains_key(name) && !candidate_by_name.contains_key(name) {
                return Err(format!(
                    "dependency candidate set {} change names absent dependency {name}",
                    self.set_id
                ));
            }
        }
        Ok(())
    }

    /// Stable candidate identity is based on exact contents, not vector order
    /// or readable set labels.
    pub fn stable_identity(&self) -> std::result::Result<ContentHash, serde_json::Error> {
        let mut normalized = self.clone();
        normalized.set_id.clear();
        normalized.baseline.set_id.clear();
        normalized.candidate.set_id.clear();
        normalized
            .baseline
            .dependencies
            .sort_by(|left, right| left.id.cmp(&right.id));
        normalized
            .candidate
            .dependencies
            .sort_by(|left, right| left.id.cmp(&right.id));
        normalized
            .changes
            .sort_by(|left, right| left.id.cmp(&right.id));
        let hash = crate::canonical_json_hash(&normalized)?;
        Ok(ContentHash::try_from(hash)
            .expect("canonical_json_hash always returns canonical SHA-256"))
    }

    pub fn stable_candidate_id(&self) -> std::result::Result<String, serde_json::Error> {
        Ok(format!(
            "dependency-candidate-{}",
            self.stable_identity()?.hex()
        ))
    }

    /// Apply an exact subset to the baseline and produce the resolution a
    /// probe must install. Unknown or internally inconsistent changes fail
    /// closed before any executor callback runs.
    pub fn resolution_for_changes(
        &self,
        changes: &[DependencyChange],
    ) -> std::result::Result<ResolvedDependencySet, String> {
        self.validate()?;
        let declared: std::collections::BTreeMap<_, _> = self
            .changes
            .iter()
            .map(|change| (change.id.as_str(), change))
            .collect();
        let mut selected = std::collections::BTreeSet::new();
        for change in changes {
            let Some(expected) = declared.get(change.id.as_str()) else {
                return Err(format!(
                    "dependency probe references unknown change {}",
                    change.id
                ));
            };
            if *expected != change {
                return Err(format!(
                    "dependency probe change {} differs from the candidate manifest",
                    change.id
                ));
            }
            if !selected.insert(change.id.as_str()) {
                return Err(format!("dependency probe repeats change {}", change.id));
            }
        }

        let mut dependencies: std::collections::BTreeMap<_, _> = self
            .baseline
            .dependencies
            .iter()
            .cloned()
            .map(|dependency| (dependency.name.clone(), dependency))
            .collect();
        let mut ordered_changes = changes.to_vec();
        ordered_changes.sort_by(|left, right| left.id.cmp(&right.id));
        for change in ordered_changes {
            match change.kind {
                DependencyChangeKind::Add => {
                    if dependencies
                        .insert(
                            change.name.clone(),
                            change
                                .after
                                .clone()
                                .expect("validated add change has an after resolution"),
                        )
                        .is_some()
                    {
                        return Err(format!(
                            "dependency add change {} replaces an existing member",
                            change.id
                        ));
                    }
                }
                DependencyChangeKind::Update => {
                    let before = change
                        .before
                        .as_ref()
                        .expect("validated update change has a before resolution");
                    if dependencies.get(&change.name) != Some(before) {
                        return Err(format!(
                            "dependency update change {} baseline member mismatch",
                            change.id
                        ));
                    }
                    dependencies.insert(
                        change.name,
                        change
                            .after
                            .expect("validated update change has an after resolution"),
                    );
                }
                DependencyChangeKind::Remove => {
                    let before = change
                        .before
                        .as_ref()
                        .expect("validated remove change has a before resolution");
                    if dependencies.get(&change.name) != Some(before) {
                        return Err(format!(
                            "dependency remove change {} baseline member mismatch",
                            change.id
                        ));
                    }
                    dependencies.remove(&change.name);
                }
            }
        }

        let mut resolved = ResolvedDependencySet {
            set_id: format!("{}-probe", self.set_id),
            ecosystem: self.baseline.ecosystem,
            package_manager: self.baseline.package_manager.clone(),
            manifest_sha256: ContentHash::sha256("0".repeat(64))
                .expect("a 64-character zero digest is valid"),
            dependencies: dependencies.into_values().collect(),
        };
        resolved.manifest_sha256 = resolved
            .expected_manifest_sha256()
            .map_err(|error| format!("cannot hash dependency probe resolution: {error}"))?;
        resolved.validate()?;
        Ok(resolved)
    }
}

/// Trusted, oracle-free portion of `.tomorrowci-dependencies.json`.
/// Expected verdicts/minimal sets belong in a separate test assertion model
/// and cannot be deserialized into this execution contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyExperimentManifest {
    pub schema_version: u32,
    pub ecosystem: Ecosystem,
    pub runtime: DependencyRuntimeIdentity,
    pub content_hash_algorithm: String,
    pub baseline: DependencySetReference,
    pub candidate: DependencyCandidateDeclaration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyRuntimeIdentity {
    pub version: String,
    pub container_image: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencySetReference {
    pub set_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyCandidateDeclaration {
    pub set_id: String,
    pub changes: Vec<DependencyChangeDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyChangeDeclaration {
    pub id: String,
    pub name: String,
    pub before: DependencyArtifactDeclaration,
    pub after: DependencyArtifactDeclaration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyArtifactDeclaration {
    pub version: String,
    pub source: String,
    pub content_sha256: ContentHash,
}

impl DependencyExperimentManifest {
    /// Materialize the exact typed transition after the caller has verified
    /// each declared source path against its content hash.
    pub fn to_candidate_set(
        &self,
        package_manager: &str,
    ) -> std::result::Result<DependencyCandidateSet, String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported dependency experiment schema {}",
                self.schema_version
            ));
        }
        if self.content_hash_algorithm != "sha256-tree-v1" {
            return Err(format!(
                "unsupported dependency content hash algorithm {:?}",
                self.content_hash_algorithm
            ));
        }
        if self.runtime.version.trim().is_empty()
            || self.runtime.container_image.trim().is_empty()
            || self.baseline.set_id.trim().is_empty()
            || self.candidate.set_id.trim().is_empty()
            || package_manager.trim().is_empty()
            || self.candidate.changes.is_empty()
        {
            return Err("dependency experiment identities and changes must not be empty".into());
        }
        validate_image_digest(&self.runtime.container_image).map_err(|error| {
            format!("dependency experiment runtime image is not immutable: {error}")
        })?;

        let mut baseline_dependencies = Vec::new();
        let mut candidate_dependencies = Vec::new();
        let mut changes = Vec::new();
        for declaration in &self.candidate.changes {
            let before = declaration.resolved(&declaration.before)?;
            let after = declaration.resolved(&declaration.after)?;
            baseline_dependencies.push(before.clone());
            candidate_dependencies.push(after.clone());
            changes.push(DependencyChange {
                id: declaration.id.clone(),
                name: declaration.name.clone(),
                kind: DependencyChangeKind::Update,
                before: Some(before),
                after: Some(after),
            });
        }

        let baseline = declared_dependency_set(
            &self.baseline.set_id,
            self.ecosystem,
            package_manager,
            baseline_dependencies,
        )?;
        let candidate = declared_dependency_set(
            &self.candidate.set_id,
            self.ecosystem,
            package_manager,
            candidate_dependencies,
        )?;
        let set = DependencyCandidateSet {
            set_id: self.candidate.set_id.clone(),
            baseline,
            candidate,
            changes,
        };
        set.validate()?;
        Ok(set)
    }
}

impl DependencyChangeDeclaration {
    fn resolved(
        &self,
        artifact: &DependencyArtifactDeclaration,
    ) -> std::result::Result<ResolvedDependency, String> {
        let dependency = ResolvedDependency {
            id: self.id.clone(),
            name: self.name.clone(),
            version: artifact.version.clone(),
            source: artifact.source.clone(),
            source_kind: DependencySourceKind::VendoredTreeSha256V1,
            content_sha256: artifact.content_sha256.clone(),
        };
        dependency.validate()?;
        Ok(dependency)
    }
}

fn declared_dependency_set(
    set_id: &str,
    ecosystem: Ecosystem,
    package_manager: &str,
    mut dependencies: Vec<ResolvedDependency>,
) -> std::result::Result<ResolvedDependencySet, String> {
    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    let mut set = ResolvedDependencySet {
        set_id: set_id.to_owned(),
        ecosystem,
        package_manager: package_manager.to_owned(),
        manifest_sha256: ContentHash::of_bytes(&[]),
        dependencies,
    };
    set.manifest_sha256 = set
        .expected_manifest_sha256()
        .map_err(|error| format!("cannot hash dependency resolution: {error}"))?;
    set.validate()?;
    Ok(set)
}

fn validate_workspace_relative_source(source: &str) -> std::result::Result<(), String> {
    validate_canonical_relative_path(source).map_err(|_| {
        format!("dependency source must be a canonical workspace-relative path: {source:?}")
    })
}

/// Validate a portable evidence/workspace-relative path without normalizing it.
/// Callers can safely compare accepted strings for uniqueness.
pub fn validate_canonical_relative_path(path: &str) -> std::result::Result<(), String> {
    let bytes = path.as_bytes();
    let drive_qualified = bytes.len() >= 2 && bytes[1] == b':';
    let absolute = path.starts_with('/') || drive_qualified;
    let has_noncanonical_component = path
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..");
    if absolute || path.contains('\\') || has_noncanonical_component {
        return Err(format!("noncanonical relative path: {path:?}"));
    }
    Ok(())
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_set: Option<DependencyCandidateSet>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_dependencies: Option<ResolvedDependencySet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub network: bool,
    pub phase: String,
}

/// Deterministically derive the package-manager commands that materialize an
/// exact dependency resolution. Both the writer and verifier consume this
/// contract so recorded commands cannot merely self-assert a resolved set.
pub fn dependency_materialization_commands(
    scenario: &Scenario,
) -> crate::Result<Option<Vec<CommandSpec>>> {
    let Some(set) = scenario.resolved_dependencies.as_ref() else {
        return Ok(None);
    };
    set.validate().map_err(crate::TcError::Config)?;
    let state = format!("/work/.tomorrowci/scenarios/{}", scenario.id);
    let command = |argv: Vec<String>| CommandSpec {
        argv,
        cwd: Some("/work".into()),
        network: false,
        phase: "fetch".into(),
    };
    let mut commands = Vec::new();
    match set.ecosystem {
        Ecosystem::Python => {
            let deps = format!("{state}/deps");
            let sources = format!("{state}/sources");
            commands.push(command(vec![
                "rm".into(),
                "-rf".into(),
                deps.clone(),
                sources.clone(),
            ]));
            commands.push(command(vec![
                "mkdir".into(),
                "-p".into(),
                deps.clone(),
                sources.clone(),
                format!("{state}/cache/pip"),
            ]));
            let mut install = vec![
                "python".into(),
                "-m".into(),
                "pip".into(),
                "install".into(),
                "--disable-pip-version-check".into(),
                "--no-index".into(),
                "--no-deps".into(),
                "--no-build-isolation".into(),
                "--no-use-pep517".into(),
                "--no-cache-dir".into(),
                "--no-compile".into(),
                "--target".into(),
                deps,
            ];
            for dependency in &set.dependencies {
                validate_dependency_destination(&dependency.id)?;
                let staged = format!("{sources}/{}", dependency.id);
                commands.push(command(vec!["mkdir".into(), "-p".into(), staged.clone()]));
                commands.push(command(vec![
                    "cp".into(),
                    "-R".into(),
                    format!("/work/{}/.", dependency.source),
                    staged.clone(),
                ]));
                install.push(staged);
            }
            commands.push(command(install));
        }
        Ecosystem::Node => {
            let project = format!("{state}/node-project");
            commands.push(command(vec!["rm".into(), "-rf".into(), project.clone()]));
            commands.push(command(vec!["mkdir".into(), "-p".into(), project.clone()]));
            let mut install = vec![
                "npm".into(),
                "install".into(),
                "--prefix".into(),
                project,
                "--offline".into(),
                "--ignore-scripts".into(),
                "--no-audit".into(),
                "--no-fund".into(),
                "--package-lock".into(),
            ];
            for dependency in &set.dependencies {
                validate_dependency_destination(&dependency.name)?;
                install.push(format!("/work/{}", dependency.source));
            }
            commands.push(command(install));
        }
        Ecosystem::Rust => {
            let deps = "/work/vendor/tomorrowci-selected".to_string();
            commands.push(command(vec![
                "mkdir".into(),
                "-p".into(),
                format!("{state}/cargo"),
                format!("{state}/target"),
            ]));
            for dependency in &set.dependencies {
                validate_dependency_destination(&dependency.name)?;
                let destination = format!("{deps}/{}", dependency.name);
                commands.push(command(vec![
                    "rm".into(),
                    "-rf".into(),
                    destination.clone(),
                ]));
                commands.push(command(vec![
                    "mkdir".into(),
                    "-p".into(),
                    destination.clone(),
                ]));
                commands.push(command(vec![
                    "cp".into(),
                    "-R".into(),
                    format!("/work/{}/.", dependency.source),
                    destination,
                ]));
            }
            commands.push(command(vec![
                "cargo".into(),
                "generate-lockfile".into(),
                "--offline".into(),
            ]));
            commands.push(command(vec![
                "cargo".into(),
                "fetch".into(),
                "--offline".into(),
                "--locked".into(),
            ]));
        }
        Ecosystem::Unknown => {
            return Err(crate::TcError::Unsupported(
                "concrete dependency materialization requires a supported ecosystem".into(),
            ));
        }
    }
    Ok(Some(commands))
}

fn validate_dependency_destination(value: &str) -> crate::Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(crate::TcError::Config(format!(
            "dependency name cannot be materialized as a local path: {value:?}"
        )));
    }
    Ok(())
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

/// Stronger evidence reference required for a live dependency reduction probe.
/// Unlike a general report link, scenario and checksum are mandatory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyProbeEvidence {
    pub run_id: String,
    pub scenario_id: String,
    pub path: String,
    pub checksum: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyProbeRequest {
    pub sequence: u32,
    pub scenario_id: String,
    pub candidate_id: String,
    pub changes: Vec<DependencyChange>,
    pub resolved_dependencies: ResolvedDependencySet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyProbeVerdict {
    Pass,
    Fail,
    Flaky,
    Blocked,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyProbeObservation {
    pub verdict: DependencyProbeVerdict,
    pub failure_hash: Option<ContentHash>,
    pub evidence: DependencyProbeEvidence,
    pub authority: EvidenceGrade,
}

/// Append-only semantic record of one callback execution against an exact
/// subset. `subset_hash` binds the full concrete changes, while `change_ids`
/// makes verifier-side subtraction checks straightforward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyProbeRecord {
    pub sequence: u32,
    pub scenario_id: String,
    pub candidate_id: String,
    pub change_ids: Vec<String>,
    pub subset_hash: ContentHash,
    pub resolved_manifest_sha256: ContentHash,
    pub verdict: DependencyProbeVerdict,
    pub failure_hash: Option<ContentHash>,
    pub evidence: DependencyProbeEvidence,
    pub authority: EvidenceGrade,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyMinimalityCheck {
    pub removed_change_id: String,
    pub remaining_change_ids: Vec<String>,
    pub probe_sequence: u32,
    pub scenario_id: String,
    pub verdict: DependencyProbeVerdict,
    pub failure_hash: Option<ContentHash>,
    pub necessary: bool,
    pub authority: EvidenceGrade,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyAdditionCheck {
    pub added_change_id: String,
    pub combined_change_ids: Vec<String>,
    pub probe_sequence: u32,
    pub scenario_id: String,
    pub verdict: DependencyProbeVerdict,
    pub failure_hash: Option<ContentHash>,
    pub irrelevant: bool,
    pub authority: EvidenceGrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyReductionStatus {
    ProvenMinimal,
    OriginalPassed,
    UnstableFailure,
    Blocked,
    Inconclusive,
}

/// Complete, verifier-recomputable output of live dependency ddmin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyReduction {
    pub candidate_set_id: String,
    pub candidate_id: String,
    pub candidate_hash: ContentHash,
    pub original_change_ids: Vec<String>,
    pub minimal_changes: Vec<DependencyChange>,
    pub probes: Vec<DependencyProbeRecord>,
    pub addition_probes: Vec<DependencyAdditionCheck>,
    pub subtraction_probes: Vec<DependencyMinimalityCheck>,
    pub stable_failure_hash: Option<ContentHash>,
    pub status: DependencyReductionStatus,
    pub authority: EvidenceGrade,
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
