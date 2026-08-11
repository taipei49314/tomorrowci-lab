//! Synthetic, index-only Git metadata for disposable exact-remote workspaces.

use std::collections::BTreeSet;
use std::path::Path;
use tomorrowci_core::{
    sha256_bytes, synthetic_git_blob_sha1, synthetic_git_index_v1, Result, SyntheticGitIndexEntry,
    SyntheticGitIndexRecord, TcError, SYNTHETIC_GIT_CONFIG, SYNTHETIC_GIT_ENV, SYNTHETIC_GIT_HEAD,
    SYNTHETIC_GIT_INDEX_KIND, SYNTHETIC_GIT_INDEX_SOURCE,
};
use tomorrowci_evidence::{
    metadata_is_alias, validate_existing_ancestors, validate_manifest_path, WorkspaceManifest,
};

#[derive(Debug, Clone)]
pub(crate) struct PreparedSyntheticGitIndex {
    bytes: Vec<u8>,
    pub(crate) record: SyntheticGitIndexRecord,
}

pub(crate) fn prepare_synthetic_git_index(
    workspace: &Path,
    manifest: &WorkspaceManifest,
    workspace_manifest_sha256: &str,
) -> Result<PreparedSyntheticGitIndex> {
    let workspace = validate_existing_ancestors(workspace)?;
    let metadata = std::fs::symlink_metadata(&workspace)?;
    if metadata_is_alias(&metadata) || !metadata.is_dir() {
        return Err(TcError::InvalidState(format!(
            "synthetic Git source is not a plain workspace: {}",
            workspace.display()
        )));
    }

    let mut entries = Vec::with_capacity(manifest.files.len());
    for (relative, expected) in &manifest.files {
        validate_manifest_path(relative).map_err(TcError::InvalidState)?;
        let path = validate_existing_ancestors(&workspace.join(relative))?;
        if !path.starts_with(&workspace) {
            return Err(TcError::InvalidState(format!(
                "synthetic Git source path escaped workspace: {relative:?}"
            )));
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata_is_alias(&metadata) || !metadata.is_file() {
            return Err(TcError::InvalidState(format!(
                "synthetic Git source is not a plain file: {relative:?}"
            )));
        }
        let bytes = std::fs::read(&path)?;
        if metadata.len() != expected.size
            || bytes.len() as u64 != expected.size
            || sha256_bytes(&bytes) != expected.sha256
        {
            return Err(TcError::Blocked(format!(
                "workspace changed while deriving synthetic Git index: {relative:?}"
            )));
        }
        entries.push(SyntheticGitIndexEntry {
            path: relative.clone(),
            size: expected.size,
            blob_sha1: synthetic_git_blob_sha1(&bytes),
        });
    }
    let bytes = synthetic_git_index_v1(&entries)?;
    let record = SyntheticGitIndexRecord {
        kind: SYNTHETIC_GIT_INDEX_KIND.into(),
        source: SYNTHETIC_GIT_INDEX_SOURCE.into(),
        workspace_manifest_sha256: workspace_manifest_sha256.into(),
        index_sha256: sha256_bytes(&bytes),
        entry_count: u64::try_from(entries.len()).map_err(|_| {
            TcError::InvalidState("synthetic Git index entry count exceeds u64".into())
        })?,
        history_present: false,
        hooks_present: false,
        object_files_present: false,
        ref_files_present: false,
        remotes_present: false,
    };
    Ok(PreparedSyntheticGitIndex { bytes, record })
}

pub(crate) fn install_synthetic_git_index(
    workspace: &Path,
    prepared: &PreparedSyntheticGitIndex,
) -> Result<()> {
    let workspace = validate_existing_ancestors(workspace)?;
    let git_dir = workspace.join(".git");
    match std::fs::symlink_metadata(&git_dir) {
        Ok(_) => {
            return Err(TcError::InvalidState(format!(
                "refusing to replace existing Git metadata in disposable workspace: {}",
                git_dir.display()
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::fs::create_dir(&git_dir)?;
    std::fs::create_dir(git_dir.join("objects"))?;
    std::fs::create_dir(git_dir.join("refs"))?;
    std::fs::write(git_dir.join("HEAD"), SYNTHETIC_GIT_HEAD)?;
    std::fs::write(git_dir.join("config"), SYNTHETIC_GIT_CONFIG)?;
    std::fs::write(git_dir.join("index"), &prepared.bytes)?;

    let actual: BTreeSet<String> = std::fs::read_dir(&git_dir)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| std::io::Error::other("synthetic Git metadata name is not UTF-8"))
        })
        .collect::<std::result::Result<_, _>>()?;
    let expected = BTreeSet::from([
        "HEAD".into(),
        "config".into(),
        "index".into(),
        "objects".into(),
        "refs".into(),
    ]);
    if actual != expected
        || std::fs::read(git_dir.join("HEAD"))? != SYNTHETIC_GIT_HEAD
        || std::fs::read(git_dir.join("config"))? != SYNTHETIC_GIT_CONFIG
        || sha256_bytes(&std::fs::read(git_dir.join("index"))?) != prepared.record.index_sha256
        || std::fs::read_dir(git_dir.join("objects"))?
            .next()
            .transpose()?
            .is_some()
        || std::fs::read_dir(git_dir.join("refs"))?
            .next()
            .transpose()?
            .is_some()
    {
        return Err(TcError::InvalidState(
            "synthetic Git metadata installation is not exact".into(),
        ));
    }
    Ok(())
}

pub(crate) fn configure_synthetic_git_environment(
    environment: &mut tomorrowci_core::EnvironmentSpec,
) -> Result<()> {
    if environment.workdir != "/work" {
        return Err(TcError::InvalidState(format!(
            "synthetic Git safe-directory contract requires /work, got {:?}",
            environment.workdir
        )));
    }
    let allowed: BTreeSet<&str> = SYNTHETIC_GIT_ENV.iter().map(|(key, _)| *key).collect();
    if let Some(key) = environment
        .env
        .keys()
        .find(|key| key.starts_with("GIT_") && !allowed.contains(key.as_str()))
    {
        return Err(TcError::InvalidState(format!(
            "target environment contains forbidden Git override: {key}"
        )));
    }
    for (key, value) in SYNTHETIC_GIT_ENV {
        match environment.env.get(*key) {
            Some(actual) if actual != value => {
                return Err(TcError::InvalidState(format!(
                    "target environment conflicts with synthetic Git contract: {key}"
                )))
            }
            Some(_) => {}
            None => {
                environment.env.insert((*key).into(), (*value).into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;
    use tomorrowci_evidence::{file_checksum, write_workspace_manifest};

    #[test]
    fn installed_index_lists_only_manifest_paths_without_git_capabilities() {
        let root = tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir_all(workspace.join("test")).unwrap();
        std::fs::write(workspace.join("package.json"), b"{}\n").unwrap();
        std::fs::write(workspace.join("test/source.test.ts"), b"test\n").unwrap();
        let manifest_path = root.path().join("workspace-manifest.json");
        let manifest = write_workspace_manifest(&workspace, &manifest_path).unwrap();
        let manifest_digest = file_checksum(&manifest_path).unwrap();
        let prepared =
            prepare_synthetic_git_index(&workspace, &manifest, &manifest_digest).unwrap();

        install_synthetic_git_index(&workspace, &prepared).unwrap();
        let output = Command::new("git")
            .args(["ls-files", "-z"])
            .current_dir(&workspace)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout,
            b"package.json\0test/source.test.ts\0".to_vec()
        );
        let staged = Command::new("git")
            .args(["ls-files", "--stage", "-z"])
            .current_dir(&workspace)
            .output()
            .unwrap();
        assert!(staged.status.success());
        let oid = |bytes: &[u8]| {
            synthetic_git_blob_sha1(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            staged.stdout,
            format!(
                "100644 {} 0\tpackage.json\0100644 {} 0\ttest/source.test.ts\0",
                oid(b"{}\n"),
                oid(b"test\n")
            )
            .into_bytes()
        );
        assert!(!workspace.join(".git/hooks").exists());
        assert!(std::fs::read_dir(workspace.join(".git/objects"))
            .unwrap()
            .next()
            .is_none());
        assert!(std::fs::read_dir(workspace.join(".git/refs"))
            .unwrap()
            .next()
            .is_none());
        assert!(!workspace.join(".git/logs").exists());
        assert!(!std::fs::read_to_string(workspace.join(".git/config"))
            .unwrap()
            .contains("remote"));
    }

    #[test]
    fn index_derivation_rejects_manifest_byte_drift() {
        let root = tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("file.txt"), b"before\n").unwrap();
        let manifest_path = root.path().join("workspace-manifest.json");
        let manifest = write_workspace_manifest(&workspace, &manifest_path).unwrap();
        let digest = file_checksum(&manifest_path).unwrap();
        std::fs::write(workspace.join("file.txt"), b"after\n").unwrap();
        assert!(prepare_synthetic_git_index(&workspace, &manifest, &digest).is_err());
    }
}
