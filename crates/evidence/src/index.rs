//! Canonical recursive evidence inventory (`evidence-index.json`).

use crate::hashutil::{hash_bytes, hash_file, normalize_hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tomorrowci_core::{Result, TcError};

pub const INDEX_NAME: &str = "evidence-index.json";
pub const CHECKSUMS_NAME: &str = "checksums.txt";
pub const GENERATION: u32 = 3;
pub const SCHEMA_VERSION: u32 = 1;

/// Closed class vocabulary for index entries (path-derived; stored value must match).
pub fn is_closed_class(class: &str) -> bool {
    matches!(
        class,
        "run-manifest"
            | "workspace-manifest"
            | "report-html"
            | "scenario"
            | "environment"
            | "fetch-commands"
            | "fetch-phase"
            | "fetch-result"
            | "fetch-stdout"
            | "fetch-stderr"
            | "test-commands"
            | "test-phase"
            | "test-result"
            | "result"
            | "stdout"
            | "stderr"
            | "failure-signature"
            | "replay-manifest"
            | "replay-script"
            | "commands"
            | "stdout-attempt"
            | "stderr-attempt"
            | "replay-attempt-result"
            | "replay-attempt-stdout"
            | "replay-attempt-stderr"
            | "replay-attempt-other"
            | "scenario-other"
            | "json"
            | "text"
            | "other"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceIndex {
    pub schema_version: u32,
    pub run_id: String,
    pub generation: u32,
    pub files: BTreeMap<String, IndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub class: String,
    pub required: bool,
    pub size: u64,
    pub sha256: String,
}

pub fn classify_path(rel: &str) -> String {
    if rel == "run.json" {
        return "run-manifest".into();
    }
    if rel == "workspace-manifest.json" {
        return "workspace-manifest".into();
    }
    if rel == "report.html" {
        return "report-html".into();
    }
    if let Some(rest) = rel.strip_prefix("scenarios/") {
        if let Some((_, file)) = rest.split_once('/') {
            return match file {
                "scenario.json" => "scenario",
                "environment.json" => "environment",
                "fetch-commands.json" => "fetch-commands",
                "fetch-phase.json" => "fetch-phase",
                "fetch-result.json" => "fetch-result",
                "fetch-stdout.log" => "fetch-stdout",
                "fetch-stderr.log" => "fetch-stderr",
                "test-commands.json" => "test-commands",
                "test-phase.json" => "test-phase",
                "test-result.json" => "test-result",
                "result.json" => "result",
                "stdout.log" => "stdout",
                "stderr.log" => "stderr",
                "failure-signature.json" => "failure-signature",
                "replay.json" => "replay-manifest",
                "replay.sh" | "replay.ps1" => "replay-script",
                "commands.json" => "commands",
                x if x.starts_with("stdout.attempt") => "stdout-attempt",
                x if x.starts_with("stderr.attempt") => "stderr-attempt",
                x if x.starts_with("replays/") => {
                    if x.ends_with("/result.json") {
                        "replay-attempt-result"
                    } else if x.ends_with("/stdout.log") {
                        "replay-attempt-stdout"
                    } else if x.ends_with("/stderr.log") {
                        "replay-attempt-stderr"
                    } else {
                        "replay-attempt-other"
                    }
                }
                _ => "scenario-other",
            }
            .into();
        }
    }
    if rel.ends_with(".json") {
        return "json".into();
    }
    if rel.ends_with(".log")
        || rel.ends_with(".md")
        || rel.ends_with(".html")
        || rel.ends_with(".txt")
    {
        return "text".into();
    }
    "other".into()
}

pub fn validate_rel_path(rel: &str) -> Result<()> {
    if rel.is_empty() || rel.starts_with('/') || rel.contains('\\') || rel.contains('\0') {
        return Err(TcError::InvalidState(format!(
            "illegal evidence path: {rel}"
        )));
    }
    if rel.contains("..") {
        return Err(TcError::InvalidState(format!("path traversal: {rel}")));
    }
    if Path::new(rel).is_absolute() {
        return Err(TcError::InvalidState(format!("absolute path: {rel}")));
    }
    Ok(())
}

/// Walk run root and collect payload files (exclude checksums.txt and evidence-index.json while building).
pub fn collect_payload_files(run_root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut out = BTreeMap::new();
    walk(run_root, run_root, &mut out)?;
    out.remove(CHECKSUMS_NAME);
    out.remove(INDEX_NAME);
    // Forbidden: scenario-level checksums (not payload; must not exist)
    let keys: Vec<_> = out.keys().cloned().collect();
    for k in keys {
        if k != CHECKSUMS_NAME && k.ends_with("/checksums.txt") {
            out.remove(&k);
        }
    }
    Ok(out)
}

/// Detect forbidden scenario-level checksum files on disk.
pub fn forbidden_scenario_checksums(run_root: &Path) -> Vec<String> {
    let mut bad = Vec::new();
    let sc = run_root.join("scenarios");
    if let Ok(rd) = std::fs::read_dir(sc) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                let p = e.path().join(CHECKSUMS_NAME);
                if p.is_file() {
                    bad.push(format!(
                        "scenarios/{}/{}",
                        e.file_name().to_string_lossy(),
                        CHECKSUMS_NAME
                    ));
                }
            }
        }
    }
    bad
}

fn walk(root: &Path, cur: &Path, out: &mut BTreeMap<String, PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(cur)? {
        let entry = entry?;
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        // Meta trees: workspace is covered by workspace-manifest.json; attestations are
        // verification meta written *after* inventory and must never be payload.
        if name == "workspace" || name == "attestations" {
            continue;
        }
        // Ignore finalize temp files if a previous run was interrupted mid-rename.
        if name.starts_with('.') && name.ends_with(".tmp") {
            continue;
        }
        if p.is_symlink() {
            return Err(TcError::InvalidState(format!(
                "symlink not allowed in evidence: {}",
                p.display()
            )));
        }
        if p.is_dir() {
            walk(root, &p, out)?;
        } else if p.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|_| TcError::InvalidState("path strip failed".into()))?
                .to_string_lossy()
                .replace('\\', "/");
            validate_rel_path(&rel)?;
            if out.insert(rel.clone(), p).is_some() {
                return Err(TcError::InvalidState(format!("duplicate path: {rel}")));
            }
        }
    }
    Ok(())
}

pub fn build_index(run_root: &Path, run_id: &str) -> Result<EvidenceIndex> {
    let files = collect_payload_files(run_root)?;
    let mut map = BTreeMap::new();
    for (rel, path) in files {
        let data = std::fs::read(&path)?;
        let sha = hash_bytes(&data);
        normalize_hash(&sha)?;
        map.insert(
            rel.clone(),
            IndexEntry {
                class: classify_path(&rel),
                required: true,
                size: data.len() as u64,
                sha256: sha,
            },
        );
    }
    Ok(EvidenceIndex {
        schema_version: SCHEMA_VERSION,
        run_id: run_id.to_string(),
        generation: GENERATION,
        files: map,
    })
}

/// Write evidence-index.json and checksums.txt (hashes all index entries + the index file itself).
pub fn finalize_inventory(run_root: &Path, run_id: &str) -> Result<EvidenceIndex> {
    let mut index = build_index(run_root, run_id)?;
    // write index to temp then rename
    let index_path = run_root.join(INDEX_NAME);
    let tmp = run_root.join(format!(".{INDEX_NAME}.tmp"));
    let body = serde_json::to_string_pretty(&index)?;
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, &index_path)?;

    // checksums: every indexed path + evidence-index.json
    let mut lines = String::new();
    for (rel, ent) in &index.files {
        lines.push_str(&format!("{}  {}\n", ent.sha256, rel));
    }
    let index_hash = hash_file(&index_path)?;
    lines.push_str(&format!("{index_hash}  {INDEX_NAME}\n"));
    let csum_tmp = run_root.join(".checksums.txt.tmp");
    std::fs::write(&csum_tmp, &lines)?;
    std::fs::rename(csum_tmp, run_root.join(CHECKSUMS_NAME))?;

    // re-read index from disk for return
    index = serde_json::from_str(&std::fs::read_to_string(index_path)?)?;
    Ok(index)
}

pub fn load_index(run_root: &Path) -> Result<EvidenceIndex> {
    let raw = std::fs::read_to_string(run_root.join(INDEX_NAME))
        .map_err(|e| TcError::Other(format!("missing evidence-index.json: {e}")))?;
    Ok(serde_json::from_str(&raw)?)
}
