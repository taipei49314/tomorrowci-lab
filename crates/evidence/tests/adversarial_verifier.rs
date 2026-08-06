//! Adversarial mutation corpus against the authorization verifier.

use chrono::Utc;
use indexmap::IndexMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use tomorrowci_core::{
    Baseline, BreakageFrontier, Ecosystem, EnvironmentSpec, EvidenceGrade, ExecutionPlan,
    ExecutionResult, FailureSignature, ProjectDetection, RepositorySnapshot, RunIdentity,
    RunManifest, Scenario, Verdict,
};
use tomorrowci_evidence::{
    finalize_run_checksums, verify_run_root, write_workspace_manifest, EvidenceLayout,
};

fn write_min_run(root: &Path) -> String {
    let run_id = "muttest01abcd".to_string();
    let layout = EvidenceLayout::create(root, &run_id).unwrap();
    let work = layout.run_root.join("workspace");
    fs::create_dir_all(&work).unwrap();
    fs::write(work.join("requirements.txt"), "pytest==7.4.4\n").unwrap();
    fs::write(work.join("app.py"), "x=1\n").unwrap();
    write_workspace_manifest(&work, &layout.run_root.join("workspace-manifest.json")).unwrap();

    let env = EnvironmentSpec {
        image_tag: "python:3.10-slim".into(),
        image: "python:3.10-slim".into(),
        image_digest: Some(
            "python@sha256:34a2c9467a0231d8c29a5ecadc219733a9393b026882b44d91616b9dae6088b6".into(),
        ),
        workdir: "/work".into(),
        env: IndexMap::new(),
        network_mode: "none".into(),
        memory_mb: 512,
        cpus: 1.0,
        pids_limit: 64,
        user: Some("65534:65534".into()),
        read_only_root: true,
        scenario_state_root: Some("/work/.tomorrowci/scenarios/py310-locked".into()),
        fetch_timeout_seconds: Some(300),
        test_timeout_seconds: Some(300),
        engine: Some("docker".into()),
        engine_version: Some("24.0".into()),
    };
    let sig = FailureSignature {
        kind: "ImportError".into(),
        summary: "MutableMapping".into(),
        normalized_hash: tomorrowci_core::sha256_str("ImportError:MutableMapping"),
        primary_frame: None,
    };
    let sc_base = Scenario {
        id: "baseline".into(),
        is_baseline: true,
        runtime: "3.9".into(),
        dependencies: "locked".into(),
        axes_changed: vec![],
        candidates: vec![],
        grade: EvidenceGrade::Observed,
    };
    let sc_fail = Scenario {
        id: "py310-locked".into(),
        is_baseline: false,
        runtime: "3.10".into(),
        dependencies: "locked".into(),
        axes_changed: vec![tomorrowci_core::EnvironmentAxis::Runtime],
        candidates: vec!["py310-locked".into()],
        grade: EvidenceGrade::Observed,
    };
    let base_env = {
        let mut e = env.clone();
        e.image_tag = "python:3.9-slim".into();
        e.image = "python:3.9-slim".into();
        e.image_digest = Some(
            "python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b".into(),
        );
        e.scenario_state_root = Some("/work/.tomorrowci/scenarios/baseline".into());
        e
    };

    let write_sc = |sc: &Scenario, env: &EnvironmentSpec, verdict: Verdict, fail: bool| {
        let d = layout.ensure_scenario(&sc.id).unwrap();
        fs::write(
            d.join("scenario.json"),
            serde_json::to_string_pretty(sc).unwrap(),
        )
        .unwrap();
        fs::write(
            d.join("environment.json"),
            serde_json::to_string_pretty(env).unwrap(),
        )
        .unwrap();
        for name in [
            "fetch-commands.json",
            "fetch-phase.json",
            "fetch-result.json",
            "fetch-stdout.log",
            "fetch-stderr.log",
            "test-commands.json",
            "test-phase.json",
            "test-result.json",
            "stdout.log",
            "stderr.log",
            "replay.json",
            "replay.sh",
            "replay.ps1",
            "commands.json",
        ] {
            fs::write(
                d.join(name),
                if name.ends_with(".json") {
                    "{}\n"
                } else {
                    "log\n"
                },
            )
            .unwrap();
        }
        let exec = ExecutionResult {
            scenario_id: sc.id.clone(),
            attempt: 1,
            verdict,
            exit_code: Some(if fail { 1 } else { 0 }),
            duration_ms: 10,
            timed_out: false,
            failure: if fail { Some(sig.clone()) } else { None },
            environment: env.clone(),
            commands: vec![],
        };
        fs::write(
            d.join("result.json"),
            serde_json::to_string_pretty(&exec).unwrap(),
        )
        .unwrap();
        if fail {
            fs::write(
                d.join("failure-signature.json"),
                serde_json::to_string_pretty(&sig).unwrap(),
            )
            .unwrap();
            fs::write(d.join("stderr.log"), "ImportError: MutableMapping\n").unwrap();
        }
        exec
    };

    let r0 = write_sc(&sc_base, &base_env, Verdict::BaselinePass, false);
    let r1 = write_sc(&sc_fail, &env, Verdict::FutureFail, true);

    let plan = ExecutionPlan {
        plan_id: "p".into(),
        scenarios: vec![sc_base, sc_fail],
        selection_notes: vec![],
        budget_max: 8,
    };
    let cfg_body = "{\n  \"version\": 1\n}\n";
    let config_hash = tomorrowci_evidence::hash_bytes(cfg_body.as_bytes());
    let identity = RunIdentity {
        source_commit: Some("deadbeef".into()),
        dirty_tree: false,
        tool_version: "0.1.1-alpha.3".into(),
        adapter_name: "python".into(),
        adapter_version: "0.1.1-alpha.3".into(),
        config_hash: config_hash.clone(),
        manifest_hashes: IndexMap::new(),
        container_engine: Some("docker".into()),
        container_engine_version: Some("24".into()),
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
    };
    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: "0.1.1-alpha.3".into(),
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        repository: RepositorySnapshot {
            source: root.display().to_string(),
            path: root.to_path_buf(),
            commit_sha: Some("deadbeef".into()),
            is_disposable_copy: true,
        },
        config_hash: config_hash.clone(),
        detection: ProjectDetection {
            ecosystem: Ecosystem::Python,
            manifests: vec!["requirements.txt".into()],
            package_manager: "pip".into(),
            confidence: 1.0,
            notes: vec![],
        },
        baseline: Baseline {
            runtime: "3.9".into(),
            dependencies: "locked".into(),
            declared_by: "config".into(),
        },
        plan,
        results: vec![r0, r1],
        frontier: BreakageFrontier {
            observed: true,
            horizon_label: Some("3.10".into()),
            first_failing_scenario: Some("py310-locked".into()),
            last_passing_scenario: Some("baseline".into()),
            changed_axes: vec![tomorrowci_core::EnvironmentAxis::Runtime],
            failure_signature: Some(sig),
            grade: EvidenceGrade::Observed,
            replay_command: None,
            notes: vec![],
        },
        evidence_root: layout.run_root.clone(),
        identity: Some(identity),
    };
    for name in [
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
    ] {
        let body = if name == "frontier.json" {
            serde_json::to_string_pretty(&manifest.frontier).unwrap()
        } else if name == "verdicts.json" {
            serde_json::to_string_pretty(&manifest.results).unwrap()
        } else if name == "plan.json" {
            serde_json::to_string_pretty(&manifest.plan).unwrap()
        } else if name == "config.normalized.json" {
            cfg_body.to_string()
        } else if name.ends_with(".json") {
            "{}".into()
        } else {
            "x".into()
        };
        fs::write(layout.run_root.join(name), body).unwrap();
    }
    fs::write(
        layout.run_root.join("run.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    finalize_run_checksums(&layout.run_root).unwrap();
    let rep = verify_run_root(&layout.run_root).unwrap();
    assert!(rep.ok, "baseline fixture must verify: {:?}", rep.errors);
    run_id
}

fn mutate_and_expect_fail(root: &Path, run_id: &str, f: impl FnOnce(&Path)) {
    let run_root = root.join(".tomorrowci/runs").join(run_id);
    f(&run_root);
    let rep = verify_run_root(&run_root).unwrap();
    assert!(
        !rep.ok,
        "expected verify FAIL after mutation, got PASS ({:?})",
        rep.errors
    );
}

#[test]
fn baseline_fixture_passes() {
    let d = tempdir().unwrap();
    let _ = write_min_run(d.path());
}

#[test]
fn tampered_stderr_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        fs::write(rr.join("scenarios/py310-locked/stderr.log"), "TAMPERED\n").unwrap();
    });
}

#[test]
fn extra_unclassified_file_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        fs::write(rr.join("evil.bin"), b"x").unwrap();
    });
}

#[test]
fn removed_checksum_entry_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let c = fs::read_to_string(rr.join("checksums.txt")).unwrap();
        let filtered: String = c
            .lines()
            .filter(|l| !l.contains("report.html"))
            .map(|l| format!("{l}\n"))
            .collect();
        fs::write(rr.join("checksums.txt"), filtered).unwrap();
    });
}

#[test]
fn missing_test_phase_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let _ = fs::remove_file(rr.join("scenarios/py310-locked/test-phase.json"));
        // also remove from index would require re-finalize; deleting file alone should fail hash/index
    });
}

#[test]
fn workspace_extra_file_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        fs::write(rr.join("workspace/extra.py"), "print(1)\n").unwrap();
    });
}

#[test]
fn run_id_mismatch_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let raw = fs::read_to_string(rr.join("run.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["run_id"] = serde_json::json!("differentid01");
        fs::write(
            rr.join("run.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        // re-hash only run.json in checksums would still fail directory vs manifest if we only change content hash
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn double_prefix_hash_rejected_in_normalize() {
    assert!(tomorrowci_evidence::normalize_hash(
        "sha256:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    .is_err());
}

#[test]
fn forged_replay_result_scenario_mismatch() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let dir = rr.join("scenarios/py310-locked/replays/attempt-1");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stdout.log"), "x").unwrap();
        fs::write(dir.join("stderr.log"), "y").unwrap();
        fs::write(
            dir.join("result.json"),
            r#"{"scenario_id":"wrong","ok":true}"#,
        )
        .unwrap();
        finalize_run_checksums(rr).unwrap();
    });
}

/// CLI verify writes attestations *after* PASS; those must not poison pre-replay verify.
#[test]
fn post_verify_attestations_do_not_break_inventory() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    let rr = d.path().join(".tomorrowci/runs").join(&id);
    let att = rr.join("attestations");
    fs::create_dir_all(&att).unwrap();
    fs::write(att.join("verification-fake.json"), r#"{"ok":true}"#).unwrap();
    fs::write(
        att.join("SHA256SUMS.txt"),
        "deadbeef  verification-fake.json\n",
    )
    .unwrap();
    let rep = verify_run_root(&rr).unwrap();
    assert!(
        rep.ok,
        "attestations must be excluded from payload inventory: {:?}",
        rep.errors
    );
}

#[test]
fn tampered_stdout_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        fs::write(rr.join("scenarios/py310-locked/stdout.log"), "TAMPERED\n").unwrap();
    });
}

#[test]
fn extra_scenario_file_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        fs::write(rr.join("scenarios/py310-locked/evil.log"), "x").unwrap();
    });
}

#[test]
fn workspace_missing_file_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let _ = fs::remove_file(rr.join("workspace/app.py"));
    });
}

#[test]
fn workspace_size_mismatch_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        // keep path present but change size/content without re-manifest
        fs::write(rr.join("workspace/app.py"), "x=1\n#pad\n").unwrap();
    });
}

#[test]
fn path_traversal_in_index_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let raw = fs::read_to_string(rr.join("evidence-index.json")).unwrap();
        let mut idx: serde_json::Value = serde_json::from_str(&raw).unwrap();
        idx["files"]["../escape.txt"] = serde_json::json!({
            "class": "other",
            "required": true,
            "size": 1,
            "sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        fs::write(
            rr.join("evidence-index.json"),
            serde_json::to_string_pretty(&idx).unwrap(),
        )
        .unwrap();
        // checksums still lists old set — structural path must fail
    });
}

#[test]
fn incomplete_replay_attempt_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let dir = rr.join("scenarios/py310-locked/replays/attempt-1");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stdout.log"), "x").unwrap();
        // missing result.json + stderr.log
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn remove_identity_rejected_even_after_reindex() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let raw = fs::read_to_string(rr.join("run.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v.as_object_mut().unwrap().remove("identity");
        fs::write(
            rr.join("run.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn forge_result_verdict_rejected_after_reindex() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let p = rr.join("scenarios/py310-locked/result.json");
        let raw = fs::read_to_string(&p).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["verdict"] = serde_json::json!("FUTURE_PASS");
        v["exit_code"] = serde_json::json!(0);
        v["failure"] = serde_json::Value::Null;
        fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn remove_workspace_authority_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let _ = fs::remove_dir_all(rr.join("workspace"));
        let _ = fs::remove_file(rr.join("workspace-manifest.json"));
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn unsupported_index_generation_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let raw = fs::read_to_string(rr.join("evidence-index.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["schema_version"] = serde_json::json!(777);
        v["generation"] = serde_json::json!(999);
        fs::write(
            rr.join("evidence-index.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        // rehash index into checksums only (semantic forgery)
        let h = tomorrowci_evidence::hash_file(&rr.join("evidence-index.json")).unwrap();
        let mut lines = String::new();
        for line in fs::read_to_string(rr.join("checksums.txt"))
            .unwrap()
            .lines()
        {
            if line.contains("evidence-index.json") {
                lines.push_str(&format!("{h}  evidence-index.json\n"));
            } else {
                lines.push_str(line);
                lines.push('\n');
            }
        }
        fs::write(rr.join("checksums.txt"), lines).unwrap();
    });
}

#[test]
fn arbitrary_index_class_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let raw = fs::read_to_string(rr.join("evidence-index.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["files"]["run.json"]["class"] = serde_json::json!("totally-arbitrary");
        v["files"]["run.json"]["required"] = serde_json::json!(false);
        fs::write(
            rr.join("evidence-index.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        let h = tomorrowci_evidence::hash_file(&rr.join("evidence-index.json")).unwrap();
        let mut lines = String::new();
        for line in fs::read_to_string(rr.join("checksums.txt"))
            .unwrap()
            .lines()
        {
            if line.contains("evidence-index.json") {
                lines.push_str(&format!("{h}  evidence-index.json\n"));
            } else {
                lines.push_str(line);
                lines.push('\n');
            }
        }
        fs::write(rr.join("checksums.txt"), lines).unwrap();
    });
}

#[test]
fn config_content_forge_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        fs::write(
            rr.join("config.normalized.json"),
            "{\n  \"forged\": true\n}\n",
        )
        .unwrap();
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn forbidden_scenario_checksums_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        fs::write(
            rr.join("scenarios/py310-locked/checksums.txt"),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  result.json\n",
        )
        .unwrap();
        // do not reindex — scenario checksums are forbidden regardless
    });
}

#[test]
fn duplicate_checksum_path_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let c = fs::read_to_string(rr.join("checksums.txt")).unwrap();
        let dup = c
            .lines()
            .find(|l| l.contains("run.json"))
            .unwrap_or("")
            .to_string();
        let mut out = c;
        out.push_str(&dup);
        out.push('\n');
        fs::write(rr.join("checksums.txt"), out).unwrap();
    });
}

#[test]
fn uppercase_hash_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let raw = fs::read_to_string(rr.join("evidence-index.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let h = v["files"]["run.json"]["sha256"]
            .as_str()
            .unwrap()
            .to_string();
        // force non-canonical SHA256: + uppercase hex
        let hex = h.trim_start_matches("sha256:");
        v["files"]["run.json"]["sha256"] =
            serde_json::json!(format!("SHA256:{}", hex.to_ascii_uppercase()));
        fs::write(
            rr.join("evidence-index.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
    });
}

#[test]
fn run_time_order_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let raw = fs::read_to_string(rr.join("run.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["started_at"] = serde_json::json!("2026-08-06T12:00:00Z");
        v["finished_at"] = serde_json::json!("2026-08-06T11:00:00Z");
        fs::write(
            rr.join("run.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn forge_frontier_horizon_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let raw = fs::read_to_string(rr.join("run.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["frontier"]["horizon_label"] = serde_json::json!("99.99");
        fs::write(
            rr.join("run.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn forge_environment_digest_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let p = rr.join("scenarios/py310-locked/environment.json");
        let raw = fs::read_to_string(&p).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["image_tag"] = serde_json::json!("python:9.9-slim");
        v["image"] = serde_json::json!("python:9.9-slim");
        v["image_digest"] = serde_json::json!(
            "python@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        finalize_run_checksums(rr).unwrap();
    });
}

#[test]
fn invalid_replay_result_json_rejected() {
    let d = tempdir().unwrap();
    let id = write_min_run(d.path());
    mutate_and_expect_fail(d.path(), &id, |rr| {
        let dir = rr.join("scenarios/py310-locked/replays/attempt-1");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("result.json"), "{not json").unwrap();
        fs::write(dir.join("stdout.log"), "x").unwrap();
        fs::write(dir.join("stderr.log"), "y").unwrap();
        finalize_run_checksums(rr).unwrap();
    });
}
