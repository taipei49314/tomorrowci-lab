use chrono::{TimeZone, Utc};
use indexmap::IndexMap;
use std::path::{Path, PathBuf};
use tomorrowci_core::{
    Baseline, BreakageFrontier, EnvironmentAxis, EnvironmentSpec, EvidenceGrade, ExecutionPlan,
    ExecutionResult, FailureSignature, ProjectDetection, RepositorySnapshot, RunManifest, Scenario,
    Verdict,
};
use tomorrowci_report::write_html_report_from_verified_root;

fn environment(tag: &str, digest: Option<&str>) -> EnvironmentSpec {
    EnvironmentSpec {
        image_tag: tag.into(),
        image: tag.into(),
        image_digest: digest.map(str::to_owned),
        workdir: "/work".into(),
        env: IndexMap::new(),
        network_mode: "none".into(),
        memory_mb: 2048,
        cpus: 1.0,
        pids_limit: 256,
        user: Some("1000:1000".into()),
        read_only_root: true,
        scenario_state_root: None,
        fetch_timeout_seconds: Some(60),
        test_timeout_seconds: Some(60),
        engine: Some("docker".into()),
        engine_version: Some("27.5.1".into()),
    }
}

fn scenario(id: &str, baseline: bool, runtime: &str) -> Scenario {
    Scenario {
        id: id.into(),
        is_baseline: baseline,
        runtime: runtime.into(),
        dependencies: "locked".into(),
        axes_changed: if baseline {
            Vec::new()
        } else {
            vec![EnvironmentAxis::Runtime]
        },
        candidates: if baseline {
            Vec::new()
        } else {
            vec![id.into()]
        },
        grade: EvidenceGrade::Observed,
        resolved_dependencies: None,
    }
}

fn manifest(run_root: &Path) -> RunManifest {
    let injection = "</script><script data-xss>window.__tomorrowciXss=true</script><img data-xss src=x onerror=alert(1)>";
    RunManifest {
        evidence_schema_version: 2,
        run_id: "browser-fixture".into(),
        tool_version: "0.2.0-alpha.1".into(),
        started_at: Utc.with_ymd_and_hms(2026, 8, 11, 1, 0, 0).unwrap(),
        finished_at: Some(Utc.with_ymd_and_hms(2026, 8, 11, 1, 1, 0).unwrap()),
        repository: RepositorySnapshot {
            source: "fixtures/node-runtime-break".into(),
            path: PathBuf::from("fixtures/node-runtime-break"),
            commit_sha: Some("0123456789abcdef0123456789abcdef01234567".into()),
            is_disposable_copy: true,
        },
        config_hash: format!("sha256:{}", "a".repeat(64)),
        detection: ProjectDetection {
            ecosystem: tomorrowci_core::Ecosystem::Node,
            manifests: vec!["package.json".into(), "package-lock.json".into()],
            package_manager: "npm".into(),
            confidence: 1.0,
            notes: vec![injection.into()],
        },
        baseline: Baseline {
            runtime: "20".into(),
            dependencies: "locked".into(),
            declared_by: "config".into(),
        },
        plan: ExecutionPlan {
            plan_id: "browser-plan".into(),
            scenarios: vec![
                scenario("baseline", true, "20"),
                scenario("node22", false, "22"),
                scenario("blocked-candidate", false, "24"),
            ],
            selection_notes: vec![format!("Untrusted note remains inert: {injection}")],
            budget_max: 3,
        },
        results: vec![
            ExecutionResult {
                scenario_id: "baseline".into(),
                attempt: 1,
                verdict: Verdict::BaselinePass,
                exit_code: Some(0),
                duration_ms: 100,
                timed_out: false,
                failure: None,
                environment: environment(
                    "node:20-bookworm",
                    Some(&format!("node@sha256:{}", "b".repeat(64))),
                ),
                commands: Vec::new(),
            },
            ExecutionResult {
                scenario_id: "node22".into(),
                attempt: 2,
                verdict: Verdict::FutureFail,
                exit_code: Some(1),
                duration_ms: 125,
                timed_out: false,
                failure: Some(FailureSignature {
                    kind: "RemovedRuntimeApi".into(),
                    summary: format!("Removed runtime API; target text: {injection}"),
                    normalized_hash: format!("sha256:{}", "c".repeat(64)),
                    primary_frame: None,
                }),
                environment: environment(
                    "node:22-bookworm",
                    Some(&format!("node@sha256:{}", "d".repeat(64))),
                ),
                commands: Vec::new(),
            },
            ExecutionResult {
                scenario_id: "blocked-candidate".into(),
                attempt: 0,
                verdict: Verdict::Blocked,
                exit_code: None,
                duration_ms: 0,
                timed_out: false,
                failure: None,
                environment: environment("node:24-bookworm", None),
                commands: Vec::new(),
            },
        ],
        frontier: BreakageFrontier {
            observed: true,
            horizon_label: Some("22".into()),
            first_failing_scenario: Some("node22".into()),
            last_passing_scenario: Some("baseline".into()),
            changed_axes: vec![EnvironmentAxis::Runtime],
            failure_signature: Some(FailureSignature {
                kind: "RemovedRuntimeApi".into(),
                summary: format!("Removed runtime API; target text: {injection}"),
                normalized_hash: format!("sha256:{}", "c".repeat(64)),
                primary_frame: None,
            }),
            grade: EvidenceGrade::Observed,
            replay_command: Some("tomorrowci replay browser-fixture --scenario node22".into()),
            notes: vec![format!(
                "Authorized from verified evidence; target text: {injection}"
            )],
        },
        evidence_root: run_root.to_path_buf(),
        identity: None,
    }
}

fn main() -> tomorrowci_core::Result<()> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| tomorrowci_core::TcError::Config("expected output report path".into()))?;
    let run_root = output
        .parent()
        .ok_or_else(|| tomorrowci_core::TcError::Config("output has no parent".into()))?;
    for attempt in [1, 2] {
        let root = run_root
            .join("scenarios/node22/replays")
            .join(format!("attempt-{attempt}"));
        std::fs::create_dir_all(&root)?;
        std::fs::write(
            root.join("result.json"),
            format!("{{\"attempt\":{attempt}}}\n"),
        )?;
    }
    let manifest = manifest(run_root);
    write_html_report_from_verified_root(&manifest, run_root, &output)?;
    println!("{}", output.display());
    Ok(())
}
