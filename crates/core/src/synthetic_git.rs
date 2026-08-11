//! Deterministic, index-only Git metadata for exact remote workspaces.
//!
//! The generated Git index contains only the paths and blob identities of a
//! separately verified workspace manifest. It intentionally contains no
//! commits, refs, object database, remotes, credentials, or hooks.

use crate::{Result, TcError};
use sha1::{Digest, Sha1};

pub const SYNTHETIC_GIT_INDEX_KIND: &str = "tomorrowci.synthetic-git-index.v1";
pub const SYNTHETIC_GIT_INDEX_SOURCE: &str = "workspace-manifest.json";
pub const SYNTHETIC_GIT_HEAD: &[u8] = b"ref: refs/heads/tomorrowci-synthetic-index\n";
pub const SYNTHETIC_GIT_CONFIG: &[u8] = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = false\n\thooksPath = .git/tomorrowci-no-hooks\n";
pub const SYNTHETIC_GIT_ENV: &[(&str, &str)] = &[
    ("GIT_CONFIG_COUNT", "1"),
    ("GIT_CONFIG_KEY_0", "safe.directory"),
    ("GIT_CONFIG_VALUE_0", "/work"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_ASKPASS", "/bin/false"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticGitIndexEntry {
    pub path: String,
    pub size: u64,
    pub blob_sha1: [u8; 20],
}

/// Compute the canonical Git blob object identity without writing an object.
pub fn synthetic_git_blob_sha1(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Encode a deterministic Git index v2 with zeroed filesystem stat fields.
///
/// Blob object identities are present only in the index. No object database is
/// created, so this provides `git ls-files` path enumeration rather than Git
/// history or object access.
pub fn synthetic_git_index_v1(entries: &[SyntheticGitIndexEntry]) -> Result<Vec<u8>> {
    let count = u32::try_from(entries.len())
        .map_err(|_| TcError::InvalidState("synthetic Git index entry count exceeds u32".into()))?;
    let mut ordered: Vec<&SyntheticGitIndexEntry> = entries.iter().collect();
    ordered.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));

    let mut previous: Option<&str> = None;
    let mut index = Vec::new();
    index.extend_from_slice(b"DIRC");
    index.extend_from_slice(&2_u32.to_be_bytes());
    index.extend_from_slice(&count.to_be_bytes());

    for entry in ordered {
        validate_synthetic_git_path(&entry.path)?;
        if previous == Some(entry.path.as_str()) {
            return Err(TcError::InvalidState(format!(
                "duplicate synthetic Git index path: {:?}",
                entry.path
            )));
        }
        previous = Some(&entry.path);
        let size = u32::try_from(entry.size).map_err(|_| {
            TcError::InvalidState(format!(
                "synthetic Git index file is too large: {:?}",
                entry.path
            ))
        })?;
        let path = entry.path.as_bytes();
        let entry_start = index.len();

        // ctime seconds/nanoseconds, mtime seconds/nanoseconds, dev, ino.
        for _ in 0..6 {
            index.extend_from_slice(&0_u32.to_be_bytes());
        }
        index.extend_from_slice(&0o100644_u32.to_be_bytes());
        // uid, gid, file size.
        index.extend_from_slice(&0_u32.to_be_bytes());
        index.extend_from_slice(&0_u32.to_be_bytes());
        index.extend_from_slice(&size.to_be_bytes());
        index.extend_from_slice(&entry.blob_sha1);
        let flags = u16::try_from(path.len().min(0x0fff)).expect("12-bit path length");
        index.extend_from_slice(&flags.to_be_bytes());
        index.extend_from_slice(path);
        index.push(0);
        while (index.len() - entry_start) % 8 != 0 {
            index.push(0);
        }
    }

    let checksum: [u8; 20] = Sha1::digest(&index).into();
    index.extend_from_slice(&checksum);
    Ok(index)
}

fn validate_synthetic_git_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['\\', '\0'])
        || path.chars().any(char::is_control)
    {
        return Err(TcError::InvalidState(format!(
            "unsafe synthetic Git index path: {path:?}"
        )));
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.eq_ignore_ascii_case(".git")
            || component.eq_ignore_ascii_case(".tomorrowci")
        {
            return Err(TcError::InvalidState(format!(
                "unsafe synthetic Git index path component: {path:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_is_deterministic_and_order_independent() {
        let a = SyntheticGitIndexEntry {
            path: "a.txt".into(),
            size: 2,
            blob_sha1: synthetic_git_blob_sha1(b"a\n"),
        };
        let b = SyntheticGitIndexEntry {
            path: "dir/b.txt".into(),
            size: 2,
            blob_sha1: synthetic_git_blob_sha1(b"b\n"),
        };
        let forward = synthetic_git_index_v1(&[a.clone(), b.clone()]).unwrap();
        let reverse = synthetic_git_index_v1(&[b, a]).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(&forward[..4], b"DIRC");
        assert_eq!(u32::from_be_bytes(forward[4..8].try_into().unwrap()), 2);
        assert_eq!(u32::from_be_bytes(forward[8..12].try_into().unwrap()), 2);
    }

    #[test]
    fn blob_identity_matches_the_known_empty_git_blob() {
        assert_eq!(
            hex::encode(synthetic_git_blob_sha1(b"")),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }

    #[test]
    fn index_rejects_metadata_and_control_paths() {
        for path in [".git/config", "dir/.tomorrowci/x", "a\nb", "../x"] {
            let entry = SyntheticGitIndexEntry {
                path: path.into(),
                size: 0,
                blob_sha1: synthetic_git_blob_sha1(b""),
            };
            assert!(synthetic_git_index_v1(&[entry]).is_err(), "{path:?}");
        }
    }
}
