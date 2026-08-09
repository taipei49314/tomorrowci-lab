//! Evidence directory layout and checksum helpers.

mod verify;

pub use verify::*;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use tomorrowci_core::{sha256_bytes, Result, RunManifest, TcError};

pub const RUNS_DIR: &str = ".tomorrowci/runs";
pub const CHECKSUM_FORMAT_V2: &str = "# tomorrowci-checksums-v2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLayout {
    pub run_root: PathBuf,
}

impl EvidenceLayout {
    pub fn create(repo_root: &Path, run_id: &str) -> Result<Self> {
        validate_identifier(run_id, "run_id").map_err(TcError::InvalidState)?;
        let repo_root = validate_existing_ancestors(repo_root)?;
        let metadata = std::fs::symlink_metadata(&repo_root)?;
        if !metadata.is_dir() {
            return Err(TcError::InvalidState(format!(
                "repository root is not a directory: {}",
                repo_root.display()
            )));
        }

        let relative = format!("{RUNS_DIR}/{run_id}");
        let run_root = safe_join(&repo_root, &relative)?;
        safe_create_dir_all(&repo_root, &format!("{relative}/scenarios"))?;
        Ok(Self { run_root })
    }

    pub fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<PathBuf> {
        let path = safe_join(&self.run_root, name)?;
        std::fs::write(&path, serde_json::to_string_pretty(value)?)?;
        validate_existing_ancestors(&path)?;
        Ok(path)
    }

    pub fn scenario_dir(&self, scenario_id: &str) -> Result<PathBuf> {
        validate_identifier(scenario_id, "scenario_id").map_err(TcError::InvalidState)?;
        safe_join(&self.run_root, &format!("scenarios/{scenario_id}"))
    }

    pub fn ensure_scenario(&self, scenario_id: &str) -> Result<PathBuf> {
        validate_identifier(scenario_id, "scenario_id").map_err(TcError::InvalidState)?;
        safe_create_dir_all(&self.run_root, &format!("scenarios/{scenario_id}"))
    }
}

pub fn file_checksum(path: &Path) -> Result<String> {
    let path = validate_existing_ancestors(path)?;
    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata_is_alias(&metadata) {
        return Err(TcError::InvalidState(format!(
            "refusing to checksum symlink/reparse point: {}",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(TcError::InvalidState(format!(
            "checksum target is not a regular file: {}",
            path.display()
        )));
    }
    let data = std::fs::read(path)?;
    Ok(sha256_bytes(&data))
}

pub fn write_checksums(dir: &Path, files: &[(String, String)]) -> Result<()> {
    let dir = validate_existing_ancestors(dir)?;
    let directory_metadata = std::fs::symlink_metadata(&dir)?;
    if metadata_is_alias(&directory_metadata) || !directory_metadata.is_dir() {
        return Err(TcError::InvalidState(format!(
            "checksum output root must be a real directory: {}",
            dir.display()
        )));
    }
    let output = safe_join(&dir, "checksums.txt")?;
    if let Ok(metadata) = std::fs::symlink_metadata(&output) {
        if metadata_is_alias(&metadata) || !metadata.is_file() {
            return Err(TcError::InvalidState(format!(
                "refusing unsafe checksum output path: {}",
                output.display()
            )));
        }
    }

    let mut entries = BTreeMap::new();
    for (name, hash) in files {
        validate_manifest_path(name).map_err(TcError::InvalidState)?;
        if name.chars().any(char::is_whitespace) {
            return Err(TcError::InvalidState(format!(
                "checksum path is not representable canonically: {name:?}"
            )));
        }
        validate_sha256(hash).map_err(TcError::InvalidState)?;
        if entries.insert(name.clone(), hash.clone()).is_some() {
            return Err(TcError::InvalidState(format!(
                "duplicate checksum path: {name}"
            )));
        }
    }

    let mut lines = format!("{CHECKSUM_FORMAT_V2}\n");
    for (name, hash) in entries {
        lines.push_str(&format!("{hash}  {name}\n"));
    }
    std::fs::write(output, lines)?;
    Ok(())
}

pub fn validate_identifier(raw: &str, label: &str) -> std::result::Result<(), String> {
    validate_manifest_path(raw).map_err(|error| format!("invalid {label}: {error}"))?;
    if raw.contains('/') || raw == "." || raw == ".." {
        return Err(format!(
            "invalid {label}: expected one canonical path component, got {raw:?}"
        ));
    }
    Ok(())
}

pub fn validate_manifest_path(raw: &str) -> std::result::Result<(), String> {
    if raw.is_empty() {
        return Err("manifest path is empty".into());
    }
    if raw.contains('\\') {
        return Err(format!("manifest path must use forward slashes: {raw:?}"));
    }
    if raw.starts_with('/') || raw.ends_with('/') || raw.contains("//") {
        return Err(format!("manifest path is not canonical: {raw:?}"));
    }
    if raw.as_bytes().get(1) == Some(&b':')
        && raw.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
    {
        return Err(format!("manifest path must be relative: {raw:?}"));
    }

    for component in raw.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!("manifest path is not canonical: {raw:?}"));
        }
        if component.contains(':') || component.contains('\0') {
            return Err(format!(
                "manifest path contains a non-portable component: {raw:?}"
            ));
        }
    }

    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(format!("manifest path must be relative: {raw:?}"));
    }
    Ok(())
}

pub(crate) fn validate_sha256(raw: &str) -> std::result::Result<(), String> {
    let Some(hex) = raw.strip_prefix("sha256:") else {
        return Err(format!(
            "checksum must use the canonical sha256:<hex> form: {raw:?}"
        ));
    };
    if hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || hex.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!(
            "checksum must contain exactly 64 lowercase hexadecimal characters: {raw:?}"
        ));
    }
    Ok(())
}

pub fn metadata_is_alias(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    false
}

pub fn validate_existing_ancestors(path: &Path) -> Result<PathBuf> {
    let absolute = lexical_absolute(path)?;
    let mut ancestors: Vec<_> = absolute.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata_is_alias(&metadata) => {
                return Err(TcError::InvalidState(format!(
                    "refusing path with symlink/reparse ancestor: {}",
                    ancestor.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(absolute)
}

pub(crate) fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_manifest_path(relative).map_err(TcError::InvalidState)?;
    let root = validate_existing_ancestors(root)?;
    let candidate = lexical_absolute(&root.join(relative))?;
    if !candidate.starts_with(&root) {
        return Err(TcError::InvalidState(format!(
            "joined path escapes root {}: {relative:?}",
            root.display()
        )));
    }
    validate_existing_ancestors(&candidate)
}

pub(crate) fn safe_create_dir_all(root: &Path, relative: &str) -> Result<PathBuf> {
    let candidate = safe_join(root, relative)?;
    std::fs::create_dir_all(&candidate)?;
    let candidate = validate_existing_ancestors(&candidate)?;
    let metadata = std::fs::symlink_metadata(&candidate)?;
    if !metadata.is_dir() {
        return Err(TcError::InvalidState(format!(
            "created path is not a directory: {}",
            candidate.display()
        )));
    }
    Ok(candidate)
}

fn lexical_absolute(path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(TcError::InvalidState(format!(
            "filesystem path is not lexically canonical: {}",
            path.display()
        )));
    }
    if cfg!(windows)
        && path
            .components()
            .any(|component| matches!(component, Component::Prefix(_)))
        && !path.is_absolute()
    {
        return Err(TcError::InvalidState(format!(
            "drive-relative filesystem path is forbidden: {}",
            path.display()
        )));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

pub fn write_run_manifest(layout: &EvidenceLayout, manifest: &RunManifest) -> Result<()> {
    layout.write_json("run.json", manifest)?;
    Ok(())
}

pub fn load_run_manifest(run_root: &Path) -> Result<RunManifest> {
    let run_root = validate_existing_ancestors(run_root)?;
    let run_json = safe_join(&run_root, "run.json")?;
    let raw = std::fs::read_to_string(run_json)
        .map_err(|e| TcError::Other(format!("missing run.json for replay: {e}")))?;
    Ok(serde_json::from_str(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn creates_layout() {
        let d = tempdir().unwrap();
        let layout = EvidenceLayout::create(d.path(), "abc123").unwrap();
        assert!(layout.run_root.exists());
        layout
            .write_json("verdicts.json", &serde_json::json!([]))
            .unwrap();
        assert!(layout.run_root.join("verdicts.json").exists());
    }

    #[test]
    fn checksum_writer_rejects_noncanonical_duplicate_and_bad_hash_entries() {
        let directory = tempdir().unwrap();
        let hash = format!("sha256:{}", "0".repeat(64));

        let traversal = vec![("../outside".to_string(), hash.clone())];
        assert!(write_checksums(directory.path(), &traversal).is_err());
        for path in ["/absolute", r"C:\absolute", "a\\b", "a/./b", "a//b"] {
            assert!(
                validate_manifest_path(path).is_err(),
                "{path:?} must not be accepted as canonical"
            );
        }

        let duplicate = vec![
            ("run.json".to_string(), hash.clone()),
            ("run.json".to_string(), hash.clone()),
        ];
        assert!(write_checksums(directory.path(), &duplicate).is_err());

        let malformed = vec![("run.json".to_string(), "not-a-hash".to_string())];
        assert!(write_checksums(directory.path(), &malformed).is_err());
    }

    #[test]
    fn layout_rejects_noncanonical_run_and_scenario_identifiers() {
        let directory = tempdir().unwrap();
        for identifier in [
            "",
            ".",
            "..",
            "../escape",
            "nested/id",
            r"nested\id",
            r"C:\escape",
            r"\\server\share",
        ] {
            assert!(
                EvidenceLayout::create(directory.path(), identifier).is_err(),
                "invalid run identifier was accepted: {identifier:?}"
            );
        }

        let layout = EvidenceLayout::create(directory.path(), "valid-run").unwrap();
        for identifier in ["", ".", "..", "../escape", "nested/id", r"C:\escape"] {
            assert!(
                layout.ensure_scenario(identifier).is_err(),
                "invalid scenario identifier was accepted: {identifier:?}"
            );
        }
        assert!(!directory.path().join("escape").exists());
    }

    #[test]
    fn layout_refuses_symlink_or_reparse_ancestors_when_supported() {
        let repository = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let alias = repository.path().join(".tomorrowci");

        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(outside.path(), &alias);

        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_dir(outside.path(), &alias);

        if created.is_err() {
            return;
        }

        let error = EvidenceLayout::create(repository.path(), "r1").unwrap_err();
        assert!(error.to_string().contains("symlink/reparse ancestor"));
        assert!(!outside.path().join("runs/r1").exists());
    }
}
