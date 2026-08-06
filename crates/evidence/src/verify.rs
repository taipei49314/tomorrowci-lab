//! Evidence authorization kernel.

use crate::hashutil::{hash_bytes, hash_file, hashes_equal, normalize_hash};
use crate::index::{
    classify_path, finalize_inventory, forbidden_scenario_checksums, is_closed_class, load_index,
    validate_rel_path, CHECKSUMS_NAME, GENERATION, INDEX_NAME, SCHEMA_VERSION,
};
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
    if index.schema_version != SCHEMA_VERSION {
        rep.err(
            "unsupported_index_schema",
            Some(INDEX_NAME),
            format!(
                "schema_version {} unsupported (require {SCHEMA_VERSION})",
                index.schema_version
            ),
        );
    }
    if index.generation != GENERATION {
        rep.err(
            "unsupported_index_generation",
            Some(INDEX_NAME),
            format!(
                "generation {} unsupported (require {GENERATION})",
                index.generation
            ),
        );
    }
    if let Ok(h) = hash_file(&run_root.join(INDEX_NAME)) {
        rep.index_hash = Some(h);
    }
    rep.semantic_checks += 1;

    // Forbidden scenario-level checksum authorities
    for p in forbidden_scenario_checksums(run_root) {
        rep.err(
            "forbidden_scenario_checksums",
            Some(&p),
            "scenario-level checksums.txt is not an authority",
        );
    }

    // --- parse checksums (reject duplicate paths) ---
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

    // verify each indexed file hash/size + checksum agreement + closed class
    for (rel, ent) in &index.files {
        if let Err(e) = validate_rel_path(rel) {
            rep.err("bad_path", Some(rel), e.to_string());
            continue;
        }
        if !is_closed_class(&ent.class) {
            rep.err(
                "invalid_index_class",
                Some(rel),
                format!("class {:?} not in closed vocabulary", ent.class),
            );
        }
        let expected_class = classify_path(rel);
        if ent.class != expected_class {
            rep.err(
                "index_class_mismatch",
                Some(rel),
                format!(
                    "stored class {:?} != path-derived {expected_class:?}",
                    ent.class
                ),
            );
        }
        // required is policy-derived; stored false on a payload path is forgery
        if !ent.required {
            rep.err(
                "index_required_false",
                Some(rel),
                "index entry required=false is not allowed for payload files",
            );
        }
        match normalize_hash(&ent.sha256) {
            Ok(canonical) => {
                if ent.sha256.trim() != canonical.as_str() {
                    rep.err(
                        "noncanonical_hash_form",
                        Some(rel),
                        "index hash not in exact canonical form",
                    );
                }
            }
            Err(e) => {
                rep.err("malformed_hash", Some(rel), e.to_string());
                continue;
            }
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

    // no extra unclassified files under run (same collector as inventory build)
    match crate::index::collect_payload_files(run_root) {
        Ok(on_disk) => {
            let disk_keys: BTreeSet<_> = on_disk.keys().cloned().collect();
            let index_keys: BTreeSet<_> = index.files.keys().cloned().collect();
            for p in disk_keys.difference(&index_keys) {
                rep.err(
                    "extra_unclassified",
                    Some(p),
                    format!("file present on disk but not in evidence-index: {p}"),
                );
            }
            for p in index_keys.difference(&disk_keys) {
                // tolerate only if path exists (race) else report
                if !run_root.join(p).is_file() {
                    rep.err(
                        "index_missing_on_disk",
                        Some(p),
                        format!("indexed path missing on disk: {p}"),
                    );
                }
            }
        }
        Err(e) => rep.err("disk_inventory", None, e.to_string()),
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
                // Identity is mandatory for authorization (RC2)
                match &m.identity {
                    None => rep.err(
                        "missing_identity",
                        Some("run.json"),
                        "run.json.identity is required",
                    ),
                    Some(id) => {
                        if id.source_commit.as_ref() != m.repository.commit_sha.as_ref() {
                            rep.err(
                                "identity_commit_mismatch",
                                Some("run.json"),
                                "identity.source_commit != repository.commit_sha",
                            );
                        }
                        if id.source_commit.as_ref().map(|s| s.trim().is_empty()) != Some(false) {
                            rep.err(
                                "identity_empty_commit",
                                Some("run.json"),
                                "identity.source_commit must be non-empty",
                            );
                        }
                        if id.tool_version.trim().is_empty()
                            || id.adapter_name.trim().is_empty()
                            || id.adapter_version.trim().is_empty()
                        {
                            rep.err(
                                "identity_incomplete",
                                Some("run.json"),
                                "identity tool/adapter fields must be non-empty",
                            );
                        }
                        if id.config_hash != m.config_hash {
                            rep.err(
                                "identity_config_hash",
                                Some("run.json"),
                                "identity.config_hash != config_hash",
                            );
                        }
                        if normalize_hash(&id.config_hash).is_err()
                            || normalize_hash(&m.config_hash).is_err()
                        {
                            rep.err(
                                "identity_config_hash_form",
                                Some("run.json"),
                                "config_hash must be canonical sha256",
                            );
                        }
                        if id.container_engine.as_ref().map(|s| s.trim().is_empty()) != Some(false)
                        {
                            rep.err(
                                "identity_missing_engine",
                                Some("run.json"),
                                "identity.container_engine required",
                            );
                        }
                        if let (Some(start), Some(finish)) = (Some(id.started_at), id.finished_at) {
                            if start > finish {
                                rep.err(
                                    "identity_time_order",
                                    Some("run.json"),
                                    "identity started_at > finished_at",
                                );
                            }
                        }
                    }
                }
                // run timestamps
                if let Some(fin) = m.finished_at {
                    if m.started_at > fin {
                        rep.err(
                            "run_time_order",
                            Some("run.json"),
                            "run started_at > finished_at",
                        );
                    }
                }
                // config.normalized.json must match config_hash
                let cfg_path = run_root.join("config.normalized.json");
                if cfg_path.is_file() {
                    if let Ok(ch) = hash_file(&cfg_path) {
                        if !hashes_equal(&ch, &m.config_hash) {
                            rep.err(
                                "config_hash_mismatch",
                                Some("config.normalized.json"),
                                "config.normalized.json bytes != run.json.config_hash",
                            );
                        }
                    }
                } else {
                    rep.err(
                        "missing_config_normalized",
                        Some("config.normalized.json"),
                        "config.normalized.json required",
                    );
                }
                // plan/result/directory sets + uniqueness
                let plan_ids_vec: Vec<_> = m.plan.scenarios.iter().map(|s| s.id.clone()).collect();
                let plan_ids: BTreeSet<_> = plan_ids_vec.iter().cloned().collect();
                if plan_ids_vec.len() != plan_ids.len() {
                    rep.err(
                        "duplicate_plan_scenario",
                        None,
                        "plan.scenarios contains duplicate scenario IDs",
                    );
                }
                let result_ids: BTreeSet<_> =
                    m.results.iter().map(|r| r.scenario_id.clone()).collect();
                if m.results.len() != result_ids.len() {
                    rep.err(
                        "duplicate_result_scenario",
                        None,
                        "results contain duplicate scenario IDs",
                    );
                }
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
                    // verdict-aware required files (exist + indexed)
                    let prefix = format!("scenarios/{}/", r.scenario_id);
                    let need = required_for_verdict(r.verdict);
                    for f in need {
                        let rel = format!("{prefix}{f}");
                        let on_disk = run_root.join(&rel).is_file();
                        let in_index = index.files.contains_key(&rel);
                        if !on_disk || !in_index {
                            if matches!(r.verdict, Verdict::Blocked) && f.starts_with("test") {
                                continue;
                            }
                            if matches!(r.verdict, Verdict::Blocked) && f.starts_with("fetch") {
                                continue;
                            }
                            if matches!(r.verdict, Verdict::Blocked)
                                && f == "failure-signature.json"
                            {
                                continue;
                            }
                            rep.err(
                                "missing_verdict_required",
                                Some(&rel),
                                format!("{:?} requires {f} (indexed+on disk)", r.verdict),
                            );
                        }
                    }
                    // Cross-file: scenario result.json must match run result summary
                    let result_path = format!("{prefix}result.json");
                    if let Ok(raw) = std::fs::read_to_string(run_root.join(&result_path)) {
                        match serde_json::from_str::<serde_json::Value>(&raw) {
                            Ok(file_r) => {
                                let fv =
                                    file_r.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
                                let expected = format!("{:?}", r.verdict).to_ascii_uppercase();
                                // serde may use SCREAMING_SNAKE
                                let expected2 = match r.verdict {
                                    Verdict::BaselinePass => "BASELINE_PASS",
                                    Verdict::BaselineInvalid => "BASELINE_INVALID",
                                    Verdict::FuturePass => "FUTURE_PASS",
                                    Verdict::FutureFail => "FUTURE_FAIL",
                                    Verdict::Flaky => "FLAKY",
                                    Verdict::Blocked => "BLOCKED",
                                    Verdict::Unsupported => "UNSUPPORTED",
                                    Verdict::Inconclusive => "INCONCLUSIVE",
                                };
                                if fv != expected2 && fv != expected {
                                    rep.err(
                                        "result_verdict_mismatch",
                                        Some(&result_path),
                                        format!(
                                            "result.json verdict {fv:?} != run results {:?}",
                                            r.verdict
                                        ),
                                    );
                                }
                                let fe = file_r.get("exit_code").and_then(|v| {
                                    if v.is_null() {
                                        None
                                    } else {
                                        v.as_i64().map(|x| x as i32)
                                    }
                                });
                                if fe != r.exit_code {
                                    rep.err(
                                        "result_exit_mismatch",
                                        Some(&result_path),
                                        "result.json exit_code != run results",
                                    );
                                }
                            }
                            Err(e) => {
                                rep.err("result_json_parse", Some(&result_path), e.to_string())
                            }
                        }
                    }
                    // environment.json vs run result environment
                    let env_path = format!("{prefix}environment.json");
                    if let Ok(raw) = std::fs::read_to_string(run_root.join(&env_path)) {
                        if let Ok(file_env) =
                            serde_json::from_str::<tomorrowci_core::EnvironmentSpec>(&raw)
                        {
                            if file_env.tag() != r.environment.tag()
                                || file_env.image_digest != r.environment.image_digest
                            {
                                rep.err(
                                    "environment_mismatch",
                                    Some(&env_path),
                                    "environment.json tag/digest != run results.environment",
                                );
                            }
                        }
                    }
                    // test-commands.json must match result.commands for test phase (when present)
                    let tc_path = format!("{prefix}test-commands.json");
                    if let Ok(raw) = std::fs::read_to_string(run_root.join(&tc_path)) {
                        if let Ok(file_cmds) =
                            serde_json::from_str::<Vec<tomorrowci_core::CommandSpec>>(&raw)
                        {
                            let result_test: Vec<_> = r
                                .commands
                                .iter()
                                .filter(|c| c.phase == "test" || c.phase.is_empty())
                                .cloned()
                                .collect();
                            // If result has commands, require equality with test-commands file
                            if !r.commands.is_empty()
                                && !file_cmds.is_empty()
                                && serde_json::to_value(&file_cmds).ok()
                                    != serde_json::to_value(
                                        &r.commands
                                            .iter()
                                            .filter(|c| c.phase != "fetch")
                                            .cloned()
                                            .collect::<Vec<_>>(),
                                    )
                                    .ok()
                                && serde_json::to_value(&file_cmds).ok()
                                    != serde_json::to_value(&result_test).ok()
                                && serde_json::to_value(&file_cmds).ok()
                                    != serde_json::to_value(&r.commands).ok()
                            {
                                // Still require file equal to something stored on result OR replay
                                let replay_path = format!("{prefix}replay.json");
                                let mut ok_mirror = false;
                                if let Ok(rj) = std::fs::read_to_string(run_root.join(&replay_path))
                                {
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&rj) {
                                        if let Some(tc) = v.get("test_commands") {
                                            if serde_json::to_value(&file_cmds).ok()
                                                == Some(tc.clone())
                                            {
                                                ok_mirror = true;
                                            }
                                        }
                                        if let Some(tc) = v.get("test_argv") {
                                            // optional shape
                                            let _ = tc;
                                        }
                                    }
                                }
                                if !ok_mirror {
                                    // Compare argv sequences
                                    let fa: Vec<Vec<String>> =
                                        file_cmds.iter().map(|c| c.argv.clone()).collect();
                                    let ra: Vec<Vec<String>> = r
                                        .commands
                                        .iter()
                                        .filter(|c| c.phase != "fetch")
                                        .map(|c| c.argv.clone())
                                        .collect();
                                    if fa != ra
                                        && fa
                                            != r.commands
                                                .iter()
                                                .map(|c| c.argv.clone())
                                                .collect::<Vec<_>>()
                                    {
                                        rep.err(
                                            "test_commands_mismatch",
                                            Some(&tc_path),
                                            "test-commands.json does not match run result commands",
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // phase timestamp invariants
                    for phase_name in ["fetch-phase.json", "test-phase.json"] {
                        let pp = format!("{prefix}{phase_name}");
                        if let Ok(raw) = std::fs::read_to_string(run_root.join(&pp)) {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                                check_phase_timestamps(&v, &pp, &mut rep);
                            }
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
                                    if let Some(fsig) = &m.frontier.failure_signature {
                                        if !hashes_equal(h, &fsig.normalized_hash) {
                                            rep.err(
                                                "frontier_signature_mismatch",
                                                Some(&sig_path),
                                                "failure-signature != frontier.failure_signature",
                                            );
                                        }
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
                        // horizon must match first-fail scenario runtime/label
                        if let Some(hl) = &m.frontier.horizon_label {
                            if let Some(sc) = m.plan.scenarios.iter().find(|s| s.id == *ff) {
                                if hl != &sc.runtime && !hl.contains(&sc.runtime) {
                                    rep.err(
                                        "frontier_horizon_mismatch",
                                        None,
                                        format!(
                                            "horizon_label {hl:?} does not match first-fail runtime {}",
                                            sc.runtime
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
                rep.semantic_checks += 5;
            }
            Err(e) => rep.err("run_json_parse", Some("run.json"), e.to_string()),
        }
    } else {
        rep.err("missing_run_json", Some("run.json"), "missing run.json");
    }

    // workspace authority is mandatory (removing both must FAIL)
    let wm_path = run_root.join("workspace-manifest.json");
    let work = run_root.join("workspace");
    if !wm_path.is_file() || !work.is_dir() {
        rep.err(
            "missing_workspace_authority",
            Some("workspace"),
            "both workspace/ and workspace-manifest.json are required",
        );
    } else {
        match serde_json::from_str::<WorkspaceManifest>(&std::fs::read_to_string(&wm_path)?) {
            Ok(wm) => {
                if wm.schema_version != 1 {
                    rep.err(
                        "unsupported_workspace_schema",
                        Some("workspace-manifest.json"),
                        format!("workspace-manifest schema_version {}", wm.schema_version),
                    );
                }
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

fn check_phase_timestamps(v: &serde_json::Value, path: &str, rep: &mut VerifyReport) {
    let start = v
        .get("started_at")
        .or_else(|| v.get("start"))
        .and_then(|x| x.as_str());
    let finish = v
        .get("finished_at")
        .or_else(|| v.get("end"))
        .and_then(|x| x.as_str());
    if let (Some(s), Some(f)) = (start, finish) {
        if let (Ok(st), Ok(ft)) = (
            chrono::DateTime::parse_from_rfc3339(s),
            chrono::DateTime::parse_from_rfc3339(f),
        ) {
            if st > ft {
                rep.err(
                    "phase_time_order",
                    Some(path),
                    "phase started_at > finished_at",
                );
            }
            if let Some(dur) = v.get("duration_ms").and_then(|x| x.as_u64()) {
                let delta = (ft - st).num_milliseconds().unsigned_abs();
                // allow 2s tolerance for rounding
                if delta.abs_diff(dur) > 2000 {
                    rep.err(
                        "phase_duration_mismatch",
                        Some(path),
                        format!("duration_ms {dur} incompatible with timestamps (delta {delta}ms)"),
                    );
                }
            }
        }
    }
}

fn check_replay_attempts(run_root: &Path, rep: &mut VerifyReport) {
    let sc_root = run_root.join("scenarios");
    if !sc_root.exists() {
        return;
    }
    // load original results for signature/digest comparison
    let run_m = load_run_manifest_loose(run_root).ok();
    for sc in std::fs::read_dir(sc_root).into_iter().flatten().flatten() {
        if !sc.path().is_dir() {
            continue;
        }
        let sid = sc.file_name().to_string_lossy().to_string();
        let orig = run_m
            .as_ref()
            .and_then(|m| m.results.iter().find(|r| r.scenario_id == sid));
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
                let raw = std::fs::read_to_string(&result_path).unwrap_or_default();
                match serde_json::from_str::<serde_json::Value>(&raw) {
                    Ok(v) => {
                        if v.get("scenario_id").and_then(|x| x.as_str()) != Some(sid.as_str()) {
                            rep.err(
                                "replay_scenario_mismatch",
                                Some(&base),
                                "replay result scenario_id mismatch",
                            );
                        }
                        if let Some(o) = orig {
                            if let Some(rd) = v.get("recorded_digest").and_then(|x| x.as_str()) {
                                if let Some(od) = &o.environment.image_digest {
                                    let norm = |d: &str| {
                                        d.split("sha256:")
                                            .nth(1)
                                            .unwrap_or(d)
                                            .chars()
                                            .take(64)
                                            .collect::<String>()
                                    };
                                    if norm(rd) != norm(od) && rd != od.as_str() {
                                        rep.err(
                                            "replay_digest_mismatch",
                                            Some(&base),
                                            "replay recorded_digest != original environment digest",
                                        );
                                    }
                                }
                            }
                            if let (Some(osig), Some(rsig)) = (
                                o.failure.as_ref().map(|f| f.normalized_hash.as_str()),
                                v.get("original_signature").and_then(|x| x.as_str()),
                            ) {
                                if !hashes_equal(osig, rsig) {
                                    rep.err(
                                        "replay_signature_mismatch",
                                        Some(&base),
                                        "replay original_signature != scenario failure signature",
                                    );
                                }
                            }
                            if let Some(oe) = v.get("original_exit").and_then(|x| x.as_i64()) {
                                if Some(oe as i32) != o.exit_code {
                                    rep.err(
                                        "replay_original_exit_mismatch",
                                        Some(&base),
                                        "replay original_exit != scenario exit",
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => rep.err(
                        "replay_result_parse",
                        Some(&format!("{base}/result.json")),
                        format!("invalid replay result JSON: {e}"),
                    ),
                }
            }
        }
    }
    rep.semantic_checks += 1;
}

fn required_for_verdict(v: Verdict) -> Vec<&'static str> {
    match v {
        // RC2: completed PASS requires full fetch+test phase evidence
        Verdict::BaselinePass | Verdict::FuturePass => vec![
            "scenario.json",
            "environment.json",
            "fetch-commands.json",
            "fetch-phase.json",
            "fetch-result.json",
            "fetch-stdout.log",
            "fetch-stderr.log",
            "test-commands.json",
            "test-phase.json",
            "test-result.json",
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
            "fetch-stdout.log",
            "fetch-stderr.log",
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
        if m.contains_key(name) {
            return Err(TcError::InvalidState(format!(
                "duplicate checksums.txt path: {name}"
            )));
        }
        m.insert(name.to_string(), nh);
    }
    Ok(m)
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
