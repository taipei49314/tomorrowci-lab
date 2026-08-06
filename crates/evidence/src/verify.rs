//! Evidence authorization kernel.

use crate::hashutil::{hash_bytes, hash_file, hashes_equal, normalize_hash};
use crate::index::{finalize_inventory, load_index, validate_rel_path, CHECKSUMS_NAME, INDEX_NAME};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tomorrowci_core::{Result, RunManifest, TcError, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub run_id: String,
    pub index_generation: Option<u32>,
    pub index_hash: Option<String>,
    pub checked_files: usize,
    pub checked_bytes: u64,
    pub semantic_checks: usize,
    pub errors: Vec<VerifyError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyError {
    pub code: String,
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub schema_version: u32,
    pub files: BTreeMap<String, WorkspaceFileMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceFileMeta {
    pub size: u64,
    pub sha256: String,
}

impl VerifyReport {
    fn err(&mut self, code: &str, path: Option<&str>, message: impl Into<String>) {
        self.ok = false;
        self.errors.push(VerifyError {
            code: code.into(),
            path: path.map(|s| s.to_string()),
            message: message.into(),
        });
    }
}

pub fn write_workspace_manifest(work: &Path, out: &Path) -> Result<WorkspaceManifest> {
    let mut files = BTreeMap::new();
    walk_source(work, work, &mut files)?;
    let m = WorkspaceManifest {
        schema_version: 1,
        files,
    };
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
        if p.is_symlink() {
            return Err(TcError::InvalidState(format!(
                "symlink escape rejected: {}",
                p.display()
            )));
        }
        if p.is_dir() {
            walk_source(root, &p, out)?;
        } else if p.is_file() {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            validate_rel_path(&rel)?;
            let data = std::fs::read(&p)?;
            out.insert(
                rel,
                WorkspaceFileMeta {
                    size: data.len() as u64,
                    sha256: hash_bytes(&data),
                },
            );
        }
    }
    Ok(())
}

/// Canonical inventory finalization (replaces incomplete finalize_run_checksums).
pub fn finalize_run_checksums(run_root: &Path) -> Result<()> {
    let run_id = run_root
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    // Prefer run.json run_id if present
    let run_id = if run_root.join("run.json").exists() {
        if let Ok(m) = load_run_manifest_loose(run_root) {
            m.run_id
        } else {
            run_id
        }
    } else {
        run_id
    };
    finalize_inventory(run_root, &run_id)?;
    Ok(())
}

fn load_run_manifest_loose(run_root: &Path) -> Result<RunManifest> {
    let raw = std::fs::read_to_string(run_root.join("run.json"))?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn verify_run(repo: &Path, run_id: &str) -> Result<VerifyReport> {
    let run_root = find_run_dir(repo, run_id);
    verify_run_root(&run_root)
}

pub fn verify_run_root(run_root: &Path) -> Result<VerifyReport> {
    let mut rep = VerifyReport {
        ok: true,
        run_id: run_root
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        index_generation: None,
        index_hash: None,
        checked_files: 0,
        checked_bytes: 0,
        semantic_checks: 0,
        errors: vec![],
    };

    if !run_root.exists() {
        rep.err(
            "missing_run_dir",
            None,
            format!("missing {}", run_root.display()),
        );
        return Ok(rep);
    }

    // --- inventory presence ---
    if !run_root.join(INDEX_NAME).exists() {
        rep.err(
            "missing_index",
            Some(INDEX_NAME),
            "missing evidence-index.json",
        );
    }
    if !run_root.join(CHECKSUMS_NAME).exists() {
        rep.err(
            "missing_checksums",
            Some(CHECKSUMS_NAME),
            "missing checksums.txt",
        );
    }
    if !rep.ok && !run_root.join(INDEX_NAME).exists() {
        // still try legacy soft path for clear errors
        rep.err(
            "legacy_or_incomplete",
            None,
            "run lacks evidence-index.json (alpha.3 inventory required)",
        );
        return Ok(rep);
    }

    let index = match load_index(run_root) {
        Ok(i) => i,
        Err(e) => {
            rep.err("index_load", Some(INDEX_NAME), e.to_string());
            return Ok(rep);
        }
    };
    rep.index_generation = Some(index.generation);
    if let Ok(h) = hash_file(&run_root.join(INDEX_NAME)) {
        rep.index_hash = Some(h);
    }
    rep.semantic_checks += 1;

    // --- parse checksums ---
    let csum_map = match parse_checksums(&run_root.join(CHECKSUMS_NAME)) {
        Ok(m) => m,
        Err(e) => {
            rep.err("checksums_parse", Some(CHECKSUMS_NAME), e.to_string());
            return Ok(rep);
        }
    };

    // exact set: checksum paths == index paths ∪ {evidence-index.json}
    let mut expected: BTreeSet<String> = index.files.keys().cloned().collect();
    expected.insert(INDEX_NAME.into());
    let csum_paths: BTreeSet<String> = csum_map.keys().cloned().collect();
    for p in expected.difference(&csum_paths) {
        rep.err(
            "checksum_entry_missing",
            Some(p),
            format!("required path not listed in checksums.txt: {p}"),
        );
    }
    for p in csum_paths.difference(&expected) {
        rep.err(
            "checksum_extra",
            Some(p),
            format!("checksums.txt lists path not in index: {p}"),
        );
    }
    rep.semantic_checks += 1;

    // verify each indexed file hash/size + checksum agreement
    for (rel, ent) in &index.files {
        if let Err(e) = validate_rel_path(rel) {
            rep.err("bad_path", Some(rel), e.to_string());
            continue;
        }
        if let Err(e) = normalize_hash(&ent.sha256) {
            rep.err("malformed_hash", Some(rel), e.to_string());
            continue;
        }
        let path = run_root.join(rel);
        if !path.is_file() {
            rep.err(
                "missing_indexed_file",
                Some(rel),
                "indexed file missing on disk",
            );
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                rep.err("read_fail", Some(rel), e.to_string());
                continue;
            }
        };
        rep.checked_files += 1;
        rep.checked_bytes += data.len() as u64;
        if data.len() as u64 != ent.size {
            rep.err(
                "size_mismatch",
                Some(rel),
                format!("size {} != indexed {}", data.len(), ent.size),
            );
        }
        let actual = hash_bytes(&data);
        if !hashes_equal(&actual, &ent.sha256) {
            rep.err(
                "hash_mismatch",
                Some(rel),
                format!("content hash mismatch for {rel}"),
            );
        }
        if let Some(csum) = csum_map.get(rel) {
            if !hashes_equal(csum, &ent.sha256) {
                rep.err(
                    "checksum_index_disagree",
                    Some(rel),
                    "checksums.txt disagrees with evidence-index",
                );
            }
        }
    }

    // evidence-index hash in checksums
    if let (Some(csum), Ok(actual)) = (
        csum_map.get(INDEX_NAME),
        hash_file(&run_root.join(INDEX_NAME)),
    ) {
        if !hashes_equal(csum, &actual) {
            rep.err(
                "index_hash_mismatch",
                Some(INDEX_NAME),
                "evidence-index.json content does not match checksums.txt",
            );
        }
        rep.checked_files += 1;
    }

    // no extra unclassified files under run (excluding workspace/ and checksums/index)
    if let Ok(on_disk) = list_run_payload_paths(run_root) {
        for p in &on_disk {
            if p == CHECKSUMS_NAME || p == INDEX_NAME {
                continue;
            }
            if !index.files.contains_key(p) {
                rep.err(
                    "extra_unclassified",
                    Some(p),
                    "file present on disk but not in evidence-index",
                );
            }
        }
        for p in index.files.keys() {
            if !on_disk.contains(p) {
                rep.err(
                    "index_missing_on_disk",
                    Some(p),
                    "indexed path missing on disk",
                );
            }
        }
    }
    rep.semantic_checks += 1;

    // --- run.json semantic checks ---
    if run_root.join("run.json").exists() {
        match load_run_manifest_loose(run_root) {
            Ok(m) => {
                if m.run_id != rep.run_id {
                    rep.err(
                        "run_id_mismatch",
                        Some("run.json"),
                        format!(
                            "directory name {} != run.json.run_id {}",
                            rep.run_id, m.run_id
                        ),
                    );
                }
                if index.run_id != m.run_id {
                    rep.err(
                        "index_run_id_mismatch",
                        Some(INDEX_NAME),
                        "evidence-index.run_id != run.json.run_id",
                    );
                }
                if let Some(id) = &m.identity {
                    if id.source_commit != m.repository.commit_sha {
                        rep.err(
                            "identity_commit_mismatch",
                            Some("run.json"),
                            "identity.source_commit != repository.commit_sha",
                        );
                    }
                    if id.config_hash != m.config_hash {
                        rep.err(
                            "identity_config_hash",
                            Some("run.json"),
                            "identity.config_hash != config_hash",
                        );
                    }
                }
                // plan/result/directory sets
                let plan_ids: BTreeSet<_> = m.plan.scenarios.iter().map(|s| s.id.clone()).collect();
                let result_ids: BTreeSet<_> =
                    m.results.iter().map(|r| r.scenario_id.clone()).collect();
                let dir_ids = scenario_dirs(run_root);
                if plan_ids != result_ids {
                    rep.err(
                        "plan_result_mismatch",
                        None,
                        "plan scenario set != results scenario set",
                    );
                }
                if plan_ids != dir_ids {
                    rep.err(
                        "plan_dir_mismatch",
                        None,
                        "plan scenario set != scenarios/ directories",
                    );
                }
                let baselines: Vec<_> = m.plan.scenarios.iter().filter(|s| s.is_baseline).collect();
                if baselines.len() != 1 {
                    rep.err(
                        "baseline_count",
                        None,
                        format!("expected exactly 1 baseline, got {}", baselines.len()),
                    );
                }
                for r in &m.results {
                    let tag = r.environment.tag();
                    if tag.contains("sha256:") {
                        rep.err(
                            "image_tag_is_digest",
                            Some(&format!("scenarios/{}/environment.json", r.scenario_id)),
                            "image_tag must not contain a digest",
                        );
                    }
                    if let Some(d) = &r.environment.image_digest {
                        if normalize_hash(d).is_err() && !d.contains("@sha256:") {
                            // allow repo@sha256:hex form
                            if !d.contains("sha256:") {
                                rep.err(
                                    "bad_digest",
                                    Some(&r.scenario_id),
                                    "image_digest missing sha256",
                                );
                            }
                        }
                    }
                    // verdict-aware required files
                    let prefix = format!("scenarios/{}/", r.scenario_id);
                    let need = required_for_verdict(r.verdict);
                    for f in need {
                        let rel = format!("{prefix}{f}");
                        if !index.files.contains_key(&rel) && !run_root.join(&rel).exists() {
                            // allow soft for BLOCKED early exit without fetch
                            if matches!(r.verdict, Verdict::Blocked) && f.starts_with("test") {
                                continue;
                            }
                            if matches!(r.verdict, Verdict::Blocked)
                                && (f.starts_with("fetch") || f == "failure-signature.json")
                            {
                                // image-resolve block may lack fetch
                                if f.starts_with("fetch") {
                                    continue;
                                }
                            }
                            rep.err(
                                "missing_verdict_required",
                                Some(&rel),
                                format!("{:?} requires {f}", r.verdict),
                            );
                        }
                    }
                    if matches!(r.verdict, Verdict::FutureFail) {
                        let sig_path = format!("{prefix}failure-signature.json");
                        if let Some(sig) = &r.failure {
                            if let Ok(raw) = std::fs::read_to_string(run_root.join(&sig_path)) {
                                if let Ok(file_sig) =
                                    serde_json::from_str::<serde_json::Value>(&raw)
                                {
                                    let h = file_sig
                                        .get("normalized_hash")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    if !hashes_equal(h, &sig.normalized_hash) {
                                        rep.err(
                                            "signature_file_mismatch",
                                            Some(&sig_path),
                                            "failure-signature.json != result.failure",
                                        );
                                    }
                                }
                            } else {
                                rep.err(
                                    "missing_failure_signature",
                                    Some(&sig_path),
                                    "FUTURE_FAIL missing failure-signature.json",
                                );
                            }
                        }
                    }
                }
                if m.frontier.observed {
                    if let Some(ff) = &m.frontier.first_failing_scenario {
                        let ok_v = m.results.iter().any(|r| {
                            r.scenario_id == *ff && matches!(r.verdict, Verdict::FutureFail)
                        });
                        if !ok_v {
                            rep.err(
                                "frontier_scenario",
                                None,
                                "first_failing_scenario is not FUTURE_FAIL in results",
                            );
                        }
                    }
                }
                rep.semantic_checks += 3;
            }
            Err(e) => rep.err("run_json_parse", Some("run.json"), e.to_string()),
        }
    } else {
        rep.err("missing_run_json", Some("run.json"), "missing run.json");
    }

    // workspace-manifest exact set
    let wm_path = run_root.join("workspace-manifest.json");
    let work = run_root.join("workspace");
    if wm_path.exists() && work.exists() {
        match serde_json::from_str::<WorkspaceManifest>(&std::fs::read_to_string(&wm_path)?) {
            Ok(wm) => {
                let mut actual = BTreeMap::new();
                if let Err(e) = walk_source(&work, &work, &mut actual) {
                    rep.err("workspace_walk", Some("workspace"), e.to_string());
                } else {
                    let akeys: BTreeSet<_> = actual.keys().cloned().collect();
                    let mkeys: BTreeSet<_> = wm.files.keys().cloned().collect();
                    for k in akeys.difference(&mkeys) {
                        rep.err(
                            "workspace_extra",
                            Some(k),
                            "extra source file not in workspace-manifest",
                        );
                    }
                    for k in mkeys.difference(&akeys) {
                        rep.err(
                            "workspace_missing",
                            Some(k),
                            "workspace-manifest file missing on disk",
                        );
                    }
                    for (k, meta) in &wm.files {
                        if let Some(act) = actual.get(k) {
                            if act.size != meta.size {
                                rep.err(
                                    "workspace_size_mismatch",
                                    Some(k),
                                    format!("size {} != {}", act.size, meta.size),
                                );
                            }
                            if !hashes_equal(&act.sha256, &meta.sha256) {
                                rep.err(
                                    "workspace_hash_mismatch",
                                    Some(k),
                                    "workspace file hash mismatch",
                                );
                            }
                            if normalize_hash(&meta.sha256).is_err() {
                                rep.err(
                                    "malformed_hash",
                                    Some(k),
                                    "workspace-manifest has malformed hash",
                                );
                            }
                        }
                    }
                }
                rep.semantic_checks += 1;
            }
            Err(e) => rep.err(
                "workspace_manifest_parse",
                Some("workspace-manifest.json"),
                e.to_string(),
            ),
        }
    }

    // replay attempt semantic checks (forged result detection if present)
    check_replay_attempts(run_root, &mut rep);

    Ok(rep)
}

fn check_replay_attempts(run_root: &Path, rep: &mut VerifyReport) {
    let sc_root = run_root.join("scenarios");
    if !sc_root.exists() {
        return;
    }
    for sc in std::fs::read_dir(sc_root).into_iter().flatten().flatten() {
        if !sc.path().is_dir() {
            continue;
        }
        let sid = sc.file_name().to_string_lossy().to_string();
        let replays = sc.path().join("replays");
        if !replays.exists() {
            continue;
        }
        for att in std::fs::read_dir(&replays).into_iter().flatten().flatten() {
            if !att.path().is_dir() {
                continue;
            }
            let base = format!(
                "scenarios/{sid}/replays/{}",
                att.file_name().to_string_lossy()
            );
            for f in ["result.json", "stdout.log", "stderr.log"] {
                let rel = format!("{base}/{f}");
                if !att.path().join(f).exists() {
                    rep.err(
                        "incomplete_replay_attempt",
                        Some(&rel),
                        "replay attempt missing required file",
                    );
                }
            }
            let result_path = att.path().join("result.json");
            if result_path.exists() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(
                    &std::fs::read_to_string(result_path).unwrap_or_default(),
                ) {
                    if v.get("scenario_id").and_then(|x| x.as_str()) != Some(sid.as_str()) {
                        rep.err(
                            "replay_scenario_mismatch",
                            Some(&base),
                            "replay result scenario_id mismatch",
                        );
                    }
                }
            }
        }
    }
    rep.semantic_checks += 1;
}

fn required_for_verdict(v: Verdict) -> Vec<&'static str> {
    match v {
        Verdict::BaselinePass | Verdict::FuturePass => vec![
            "scenario.json",
            "environment.json",
            "fetch-commands.json",
            "test-commands.json",
            "result.json",
            "stdout.log",
            "stderr.log",
            "replay.json",
        ],
        Verdict::FutureFail => vec![
            "scenario.json",
            "environment.json",
            "fetch-commands.json",
            "fetch-phase.json",
            "fetch-result.json",
            "test-commands.json",
            "test-phase.json",
            "test-result.json",
            "result.json",
            "stdout.log",
            "stderr.log",
            "failure-signature.json",
            "replay.json",
            "replay.sh",
            "replay.ps1",
        ],
        Verdict::Blocked => vec!["scenario.json", "environment.json", "result.json"],
        Verdict::Flaky => vec![
            "scenario.json",
            "environment.json",
            "result.json",
            "stdout.log",
            "stderr.log",
        ],
        _ => vec!["scenario.json", "result.json"],
    }
}

fn scenario_dirs(run_root: &Path) -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    let sc = run_root.join("scenarios");
    if let Ok(rd) = std::fs::read_dir(sc) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                s.insert(e.file_name().to_string_lossy().to_string());
            }
        }
    }
    s
}

fn parse_checksums(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    let text = std::fs::read_to_string(path)?;
    for line in text.lines() {
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
        let nh = normalize_hash(hash)?;
        validate_rel_path(name)?;
        m.insert(name.to_string(), nh);
    }
    Ok(m)
}

fn list_run_payload_paths(run_root: &Path) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    fn walk(root: &Path, cur: &Path, out: &mut BTreeSet<String>) -> Result<()> {
        for entry in std::fs::read_dir(cur)? {
            let entry = entry?;
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "workspace" || name == "attestations" {
                continue;
            }
            if p.is_dir() {
                walk(root, &p, out)?;
            } else if p.is_file() {
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel.ends_with("/checksums.txt") {
                    continue;
                }
                out.insert(rel);
            }
        }
        Ok(())
    }
    walk(run_root, run_root, &mut out)?;
    Ok(out)
}

pub fn find_run_dir(cwd: &Path, run_id: &str) -> PathBuf {
    let direct = cwd.join(".tomorrowci/runs").join(run_id);
    if direct.exists() {
        return direct;
    }
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

pub fn write_verification_attestation(
    run_root: &Path,
    report: &VerifyReport,
    tool_version: &str,
) -> Result<PathBuf> {
    let att_dir = run_root.join("attestations");
    std::fs::create_dir_all(&att_dir)?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let name = format!("verification-{ts}.json");
    let path = att_dir.join(&name);
    let body = serde_json::json!({
        "schema_version": 1,
        "tool_version": tool_version,
        "run_id": report.run_id,
        "ok": report.ok,
        "index_hash": report.index_hash,
        "index_generation": report.index_generation,
        "checked_files": report.checked_files,
        "checked_bytes": report.checked_bytes,
        "semantic_checks": report.semantic_checks,
        "errors": report.errors,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    });
    let bytes = serde_json::to_vec_pretty(&body)?;
    std::fs::write(&path, &bytes)?;
    let h = hash_bytes(&bytes);
    let mut sums = String::new();
    let sums_path = att_dir.join("SHA256SUMS.txt");
    if sums_path.exists() {
        sums = std::fs::read_to_string(&sums_path)?;
    }
    sums.push_str(&format!("{h}  {name}\n"));
    std::fs::write(sums_path, sums)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvidenceLayout;
    use tempfile::tempdir;

    #[test]
    fn verifier_rejects_missing_index() {
        let d = tempdir().unwrap();
        let layout = EvidenceLayout::create(d.path(), "r1").unwrap();
        let rep = verify_run_root(&layout.run_root).unwrap();
        assert!(!rep.ok);
        assert!(rep.errors.iter().any(|e| e.code == "missing_index"));
    }
}
