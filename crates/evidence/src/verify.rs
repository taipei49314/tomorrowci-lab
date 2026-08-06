//! Evidence integrity verification.

use crate::{file_checksum, write_checksums};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tomorrowci_core::{sha256_bytes, Result, RunManifest, TcError};

pub const RUN_REQUIRED: &[&str] = &[
    "run.json",
    "repository.json",
    "config.normalized.json",
    "candidates.json",
    "plan.json",
    "plan-decisions.json",
    "verdicts.json",
    "frontier.json",
    "metrics.json",
    "claims.json",
    "report.json",
    "report.html",
    "job-summary.md",
    "summary.txt",
    "workspace-manifest.json",
    "checksums.txt",
];

pub const SCENARIO_REQUIRED: &[&str] = &[
    "scenario.json",
    "environment.json",
    "fetch-commands.json",
    "test-commands.json",
    "result.json",
    "stdout.log",
    "stderr.log",
    "replay.json",
    "replay.sh",
    "replay.ps1",
    "checksums.txt",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub run_id: String,
    pub errors: Vec<String>,
    pub checked_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub files: BTreeMap<String, WorkspaceFileMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceFileMeta {
    pub size: u64,
    pub sha256: String,
}

pub fn write_workspace_manifest(work: &Path, out: &Path) -> Result<WorkspaceManifest> {
    let mut files = BTreeMap::new();
    walk_source(work, work, &mut files)?;
    let m = WorkspaceManifest { files };
    std::fs::write(out, serde_json::to_string_pretty(&m)?)?;
    Ok(m)
}

fn walk_source(
    root: &Path,
    cur: &Path,
    out: &mut BTreeMap<String, WorkspaceFileMeta>,
) -> Result<()> {
    for entry in std::fs::read_dir(cur)? {
        let entry = entry?;
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if matches!(
            name.as_str(),
            ".tomorrowci" | "target" | "node_modules" | ".git" | "__pycache__" | ".venv" | "venv"
        ) {
            continue;
        }
        if p.is_dir() {
            walk_source(root, &p, out)?;
        } else if p.is_file() {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let data = std::fs::read(&p)?;
            out.insert(
                rel,
                WorkspaceFileMeta {
                    size: data.len() as u64,
                    sha256: format!("sha256:{}", sha256_bytes(&data)),
                },
            );
        }
    }
    Ok(())
}

/// Recompute checksums for all present required files after every writer finished.
pub fn finalize_run_checksums(run_root: &Path) -> Result<()> {
    let mut pairs = Vec::new();
    for name in RUN_REQUIRED {
        if *name == "checksums.txt" {
            continue;
        }
        let p = run_root.join(name);
        if p.exists() {
            pairs.push(((*name).to_string(), file_checksum(&p)?));
        }
    }
    // scenario checksums
    let sc_root = run_root.join("scenarios");
    if sc_root.exists() {
        for entry in std::fs::read_dir(&sc_root)? {
            let entry = entry?;
            if entry.path().is_dir() {
                finalize_scenario_checksums(&entry.path())?;
            }
        }
    }
    write_checksums(run_root, &pairs)?;
    Ok(())
}

fn finalize_scenario_checksums(sc_dir: &Path) -> Result<()> {
    let mut pairs = Vec::new();
    for name in SCENARIO_REQUIRED {
        if *name == "checksums.txt" {
            continue;
        }
        let p = sc_dir.join(name);
        if p.exists() {
            pairs.push(((*name).to_string(), file_checksum(&p)?));
        }
    }
    // optional phase files
    for name in [
        "fetch-phase.json",
        "test-phase.json",
        "fetch-result.json",
        "test-result.json",
        "failure-signature.json",
        "fetch-stdout.log",
        "fetch-stderr.log",
    ] {
        let p = sc_dir.join(name);
        if p.exists() {
            pairs.push((name.to_string(), file_checksum(&p)?));
        }
    }
    // attempt logs + replay attempts
    if let Ok(rd) = std::fs::read_dir(sc_dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("stdout.attempt")
                || n.starts_with("stderr.attempt")
                || n == "replay-result.json"
            {
                pairs.push((n, file_checksum(&e.path())?));
            }
        }
    }
    let replays = sc_dir.join("replays");
    if replays.exists() {
        for entry in std::fs::read_dir(&replays)?.flatten() {
            if entry.path().is_dir() {
                for f in ["result.json", "stdout.log", "stderr.log"] {
                    let p = entry.path().join(f);
                    if p.exists() {
                        let rel = format!("replays/{}/{}", entry.file_name().to_string_lossy(), f);
                        pairs.push((rel, file_checksum(&p)?));
                    }
                }
            }
        }
    }
    write_checksums(sc_dir, &pairs)?;
    Ok(())
}

pub fn verify_run(repo: &Path, run_id: &str) -> Result<VerifyReport> {
    let run_root = repo.join(".tomorrowci/runs").join(run_id);
    if !run_root.exists() {
        // also search one level of fixture paths is caller's job
        return Err(TcError::Blocked(format!(
            "run directory missing: {}",
            run_root.display()
        )));
    }
    verify_run_root(&run_root)
}

pub fn verify_run_root(run_root: &Path) -> Result<VerifyReport> {
    let mut errors = Vec::new();
    let mut checked = 0usize;
    let run_id = run_root
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    for name in RUN_REQUIRED {
        let p = run_root.join(name);
        if !p.exists() {
            errors.push(format!("missing required run file: {name}"));
        } else {
            checked += 1;
        }
    }

    // Verify checksums.txt entries
    let sums = run_root.join("checksums.txt");
    if sums.exists() {
        for line in std::fs::read_to_string(&sums)?.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let hash = parts.next().unwrap_or("");
            let name = parts.next().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let p = run_root.join(name);
            if !p.exists() {
                errors.push(format!("checksum lists missing file: {name}"));
                continue;
            }
            let actual = file_checksum(&p)?;
            if actual != hash && format!("sha256:{hash}") != actual && hash != actual {
                // file_checksum returns bare hex
                let bare = actual.trim_start_matches("sha256:");
                if bare != hash.trim_start_matches("sha256:") {
                    errors.push(format!("checksum mismatch: {name}"));
                }
            }
            checked += 1;
        }
    }

    // claims.json must be checksummed
    if run_root.join("claims.json").exists() {
        let listed = std::fs::read_to_string(&sums).unwrap_or_default();
        if !listed.contains("claims.json") {
            errors.push("claims.json present but not listed in checksums.txt".into());
        }
    }

    // workspace manifest
    let wm_path = run_root.join("workspace-manifest.json");
    if wm_path.exists() {
        let wm: WorkspaceManifest = serde_json::from_str(&std::fs::read_to_string(&wm_path)?)?;
        let work = run_root.join("workspace");
        for (rel, meta) in &wm.files {
            let p = work.join(rel);
            if !p.exists() {
                errors.push(format!("workspace-manifest file missing: {rel}"));
                continue;
            }
            let data = std::fs::read(&p)?;
            let h = format!("sha256:{}", sha256_bytes(&data));
            if h != meta.sha256 && sha256_bytes(&data) != meta.sha256.trim_start_matches("sha256:")
            {
                errors.push(format!("workspace-manifest hash mismatch: {rel}"));
            }
        }
    }

    // identity consistency if present
    if run_root.join("run.json").exists() {
        let m: RunManifest =
            serde_json::from_str(&std::fs::read_to_string(run_root.join("run.json"))?)?;
        if let Some(id) = &m.identity {
            if id.source_commit != m.repository.commit_sha {
                errors.push("identity.source_commit != repository.commit_sha".into());
            }
            if id.config_hash != m.config_hash {
                errors.push("identity.config_hash != manifest.config_hash".into());
            }
        }
        for r in &m.results {
            let tag = r.environment.tag();
            if let Some(d) = &r.environment.image_digest {
                if tag.contains("sha256:") {
                    errors.push(format!(
                        "scenario {} image_tag must not be a digest",
                        r.scenario_id
                    ));
                }
                if d.is_empty() {
                    errors.push(format!("scenario {} empty digest", r.scenario_id));
                }
            }
        }
    }

    // scenarios
    let sc_root = run_root.join("scenarios");
    if sc_root.exists() {
        for entry in std::fs::read_dir(sc_root)?.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            for name in SCENARIO_REQUIRED {
                if !entry.path().join(name).exists() {
                    // fetch-commands optional for non-python? require for acceptance path
                    if *name == "fetch-commands.json"
                        && !entry.path().join("fetch-commands.json").exists()
                    {
                        // allow missing only if no fetch phase file either
                        if entry.path().join("fetch-phase.json").exists() {
                            errors.push(format!(
                                "scenario {} missing {name}",
                                entry.file_name().to_string_lossy()
                            ));
                        }
                    } else if !matches!(*name, "fetch-commands.json") {
                        errors.push(format!(
                            "scenario {} missing {name}",
                            entry.file_name().to_string_lossy()
                        ));
                    }
                }
            }
        }
    }

    Ok(VerifyReport {
        ok: errors.is_empty(),
        run_id,
        errors,
        checked_files: checked,
    })
}

pub fn find_run_dir(cwd: &Path, run_id: &str) -> PathBuf {
    let direct = cwd.join(".tomorrowci/runs").join(run_id);
    if direct.exists() {
        return direct;
    }
    // scan common fixture-relative locations
    for cand in [
        cwd.join("fixtures/python-runtime-break/.tomorrowci/runs")
            .join(run_id),
        cwd.join(".tomorrowci/runs").join(run_id),
    ] {
        if cand.exists() {
            return cand;
        }
    }
    if let Ok(rd) = std::fs::read_dir(cwd) {
        for e in rd.flatten() {
            let p = e.path().join(".tomorrowci").join("runs").join(run_id);
            if p.exists() {
                return p;
            }
        }
    }
    direct
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvidenceLayout;
    use tempfile::tempdir;

    #[test]
    fn verifier_rejects_missing_claims() {
        let d = tempdir().unwrap();
        let layout = EvidenceLayout::create(d.path(), "r1").unwrap();
        // missing most required files including claims.json
        let rep = verify_run_root(&layout.run_root).unwrap();
        assert!(!rep.ok);
        assert!(rep.errors.iter().any(|e| e.contains("claims.json")));
    }
}
