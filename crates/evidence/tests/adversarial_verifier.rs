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
    let identity = RunIdentity {
        source_commit: Some("deadbeef".into()),
        dirty_tree: false,
        tool_version: "0.1.1-alpha.3".into(),
        adapter_name: "python".into(),
        adapter_version: "0.1.1-alpha.3".into(),
        config_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .into(),
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
        config_hash: identity.config_hash.clone(),
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
