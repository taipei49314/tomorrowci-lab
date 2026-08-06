//! Full scan orchestration with explicit scenario lifecycle:
//! IMAGE_RESOLVE → WORKSPACE_PREPARE → FETCH → TEST → CLASSIFY → EVIDENCE_FINALIZE

use crate::engine::{ContainerExecutor, ExecutionContext, ScenarioExecutor};
use chrono::Utc;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tomorrowci_adapter_node::NodeAdapter;
use tomorrowci_adapter_python::{python_fetch_commands, PythonAdapter};
use tomorrowci_adapter_rust::RustAdapter;
use tomorrowci_adapters::EcosystemAdapter;
use tomorrowci_core::{
    classify_from_reruns, compute_breakage_frontier, ddmin_axes, plan_scenarios, Baseline,
    CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec, EvidenceGrade,
    ExecutionResult, FailureSignature, ProjectDetection, RawExecutionResult, RepositorySnapshot,
    Result, RunManifest, Scenario, TcError, Verdict,
};
use tomorrowci_evidence::{write_checksums, write_run_manifest, EvidenceLayout};
use tomorrowci_metrics::ScanMetrics;
use tomorrowci_report::{write_github_job_summary, write_html_report, write_json_report};
use tomorrowci_sandbox::{
    make_disposable_copy, prepare_scenario_state, shell_join, MAX_SCENARIO_ARTIFACTS,
};
use uuid::Uuid;

pub struct ScanOptions {
    pub config: Config,
    pub allow_scripted: bool,
}

pub struct ScanOutcome {
    pub manifest: RunManifest,
    pub evidence_root: PathBuf,
    pub terminal_summary: String,
    pub metrics: ScanMetrics,
}

#[derive(Debug, Clone, Serialize)]
struct PhaseResult {
    phase: String,
    ok: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    network: String,
    image: String,
    image_digest: Option<String>,
    argv: Vec<Vec<String>>,
    started_at: String,
    finished_at: String,
    detail: String,
}

/// Auto-detect ecosystem and run a full local scan.
pub fn scan_local(repo: &Path, opts: ScanOptions) -> Result<ScanOutcome> {
    let py = PythonAdapter.detect(repo);
    if py.supported {
        return scan_with_adapter(repo, &PythonAdapter, opts, py.detection);
    }
    let node = NodeAdapter.detect(repo);
    if node.supported {
        return scan_with_adapter(repo, &NodeAdapter, opts, node.detection);
    }
    let rust = RustAdapter.detect(repo);
    if rust.supported {
        return scan_with_adapter(repo, &RustAdapter, opts, rust.detection);
    }
    Err(TcError::Unsupported(
        "no supported ecosystem detected (need Python, Node/npm, or Rust/cargo manifests)".into(),
    ))
}

pub fn scan_with_adapter(
    repo: &Path,
    adapter: &dyn EcosystemAdapter,
    opts: ScanOptions,
    detection: ProjectDetection,
) -> Result<ScanOutcome> {
    let config = opts.config;
    let wall_start = Instant::now();
    let run_started = Utc::now();
    let run_id = Uuid::new_v4().to_string().replace('-', "")[..12].to_string();
    let layout = EvidenceLayout::create(repo, &run_id)?;

    let work = layout.run_root.join("workspace");
    make_disposable_copy(repo, &work)?;

    // Byte-for-byte original unchanged: we only write under .tomorrowci/runs
    let baseline = adapter.baseline(repo, &config)?;
    let rt_cands = adapter.candidates(&baseline, &config)?;
    let dep_cands = dependency_candidates(&baseline, &config);

    let (plan, decisions) = plan_scenarios(&baseline, &rt_cands, &dep_cands, &config);
    layout.write_json("plan.json", &plan)?;
    layout.write_json("plan-decisions.json", &decisions)?;
    layout.write_json("candidates.json", &rt_cands)?;
    layout.write_json(
        "repository.json",
        &RepositorySnapshot {
            source: repo.display().to_string(),
            path: repo.to_path_buf(),
            commit_sha: git_head(repo),
            is_disposable_copy: true,
        },
    )?;
    layout.write_json("config.normalized.json", &config)?;

    let executor: Box<dyn ScenarioExecutor> = match ContainerExecutor::detect() {
        Ok(e) => Box::new(e),
        Err(e) if opts.allow_scripted => {
            return Err(TcError::Blocked(format!(
                "sandbox unavailable ({e}); set scripted harness in tests only"
            )));
        }
        Err(e) => return Err(e),
    };

    let mut results: Vec<ExecutionResult> = Vec::new();
    let mut ordered_for_frontier: Vec<(Scenario, ExecutionResult)> = Vec::new();
    let mut baseline_ok = false;
    let mut confirmed_first_fail = false;
    let mut first_fail_scenario: Option<String> = None;

    let eco = detection.ecosystem;
    let is_scripted = executor.name() == "scripted";

    for scenario in &plan.scenarios {
        let mut env = adapter.materialize(scenario, &work)?;
        env.image = normalize_image(eco, &scenario.runtime);
        env.memory_mb = config.sandbox.memory_mb;
        env.cpus = config.sandbox.cpus;
        env.pids_limit = config.sandbox.pids_limit;

        let sc_dir = layout.ensure_scenario(&scenario.id)?;
        // Per-scenario isolated state under workspace/.tomorrowci/<scenario_id>
        let sc_state = work.join(".tomorrowci").join(&scenario.id);
        std::fs::create_dir_all(sc_state.join("venv"))?;
        std::fs::create_dir_all(sc_state.join("cache").join("pip"))?;
        // Also prepare default paths used by Python adapter
        prepare_scenario_state(&work)?;

        // IMAGE_RESOLVE
        let digest = match executor.ensure_image(&env.image) {
            Ok(d) => d,
            Err(e) => {
                let blocked = blocked_result(scenario, &env, &[], &e.to_string());
                write_phase(
                    &sc_dir,
                    "image-resolve",
                    false,
                    None,
                    false,
                    0,
                    "n/a",
                    &env.image,
                    None,
                    &[],
                    &e.to_string(),
                )?;
                persist_scenario_artifacts(
                    &sc_dir,
                    scenario,
                    &env,
                    &[],
                    &[],
                    None,
                    None,
                    &blocked,
                    executor.engine_label(),
                    None,
                )?;
                results.push(blocked.clone());
                ordered_for_frontier.push((scenario.clone(), blocked));
                if scenario.is_baseline {
                    break;
                }
                continue;
            }
        };
        env.image_digest = Some(digest.clone());
        // Execute using digest-pinned ref when possible
        if digest.contains("@sha256:") {
            env.image = digest.clone();
        } else if digest.starts_with("sha256:") && !env.image.contains('@') {
            // keep tag for pull identity but record digest; container run uses digest via engine
        }

        let test_commands = build_scenario_commands(adapter, scenario, &config, &work)?;
        let fetch_cmds = match build_fetch_commands(eco, scenario, &work, is_scripted) {
            Ok(c) => c,
            Err(TcError::Unsupported(msg)) => {
                let mut r = blocked_result(scenario, &env, &test_commands, &msg);
                r.verdict = Verdict::Unsupported;
                persist_scenario_artifacts(
                    &sc_dir,
                    scenario,
                    &env,
                    &[],
                    &test_commands,
                    None,
                    None,
                    &r,
                    executor.engine_label(),
                    None,
                )?;
                results.push(r.clone());
                ordered_for_frontier.push((scenario.clone(), r));
                continue;
            }
            Err(e) => return Err(e),
        };

        layout_write_scenario_meta(&sc_dir, scenario, &env, &test_commands)?;
        std::fs::write(
            sc_dir.join("fetch-commands.json"),
            serde_json::to_string_pretty(&fetch_cmds)?,
        )?;
        std::fs::write(
            sc_dir.join("test-commands.json"),
            serde_json::to_string_pretty(&test_commands)?,
        )?;

        // FETCH
        let mut fetch_raw: Option<RawExecutionResult> = None;
        if let Some(ref fcmds) = fetch_cmds {
            let fetch_start = Utc::now();
            let fr = match executor.execute(&ExecutionContext {
                workspace: &work,
                scenario,
                environment: &env,
                commands: fcmds,
                timeout: Duration::from_secs(config.execution.timeout_seconds.min(600)),
                network: "bridge",
            }) {
                Ok(r) => r,
                Err(e) => {
                    let blocked = blocked_result(scenario, &env, fcmds, &e.to_string());
                    write_phase(
                        &sc_dir,
                        "fetch",
                        false,
                        None,
                        false,
                        0,
                        "bridge",
                        &env.image,
                        env.image_digest.clone(),
                        fcmds,
                        &e.to_string(),
                    )?;
                    persist_scenario_artifacts(
                        &sc_dir,
                        scenario,
                        &env,
                        fcmds,
                        &test_commands,
                        None,
                        None,
                        &blocked,
                        executor.engine_label(),
                        None,
                    )?;
                    results.push(blocked.clone());
                    ordered_for_frontier.push((scenario.clone(), blocked));
                    if scenario.is_baseline {
                        break;
                    }
                    continue;
                }
            };
            let fetch_ok = fr.exit_code == Some(0) && !fr.timed_out;
            write_raw_logs(&sc_dir, "fetch", &fr)?;
            write_phase(
                &sc_dir,
                "fetch",
                fetch_ok,
                fr.exit_code,
                fr.timed_out,
                fr.duration_ms,
                "bridge",
                &env.image,
                env.image_digest.clone(),
                fcmds,
                if fetch_ok { "ok" } else { "fetch failed" },
            )?;
            std::fs::write(
                sc_dir.join("fetch-result.json"),
                serde_json::to_string_pretty(&fr_json(&fr, fetch_start))?,
            )?;
            if !fetch_ok {
                let mut blocked = blocked_result(
                    scenario,
                    &env,
                    fcmds,
                    "dependency fetch failed; test phase not executed",
                );
                blocked.exit_code = fr.exit_code;
                blocked.duration_ms = fr.duration_ms;
                blocked.timed_out = fr.timed_out;
                blocked.failure = Some(adapter.normalize_failure(&fr));
                persist_scenario_artifacts(
                    &sc_dir,
                    scenario,
                    &env,
                    fcmds,
                    &test_commands,
                    Some(&fr),
                    None,
                    &blocked,
                    executor.engine_label(),
                    None,
                )?;
                results.push(blocked.clone());
                ordered_for_frontier.push((scenario.clone(), blocked));
                if scenario.is_baseline {
                    baseline_ok = false;
                    break;
                }
                continue;
            }
            fetch_raw = Some(fr);
        }

        // TEST with reruns
        let reruns = if scenario.is_baseline {
            1
        } else {
            config.execution.reruns_on_failure.max(1)
        };

        let mut attempt_pass: Vec<bool> = Vec::new();
        let mut last_raw = None;

        for attempt in 1..=reruns {
            let raw = executor.execute(&ExecutionContext {
                workspace: &work,
                scenario,
                environment: &env,
                commands: &test_commands,
                timeout: Duration::from_secs(config.execution.timeout_seconds),
                network: "none",
            })?;

            let pass = raw.exit_code == Some(0) && !raw.timed_out;
            attempt_pass.push(pass);
            if artifact_count(&sc_dir) < MAX_SCENARIO_ARTIFACTS {
                std::fs::write(
                    sc_dir.join(format!("stdout.attempt{attempt}.log")),
                    &raw.stdout,
                )?;
                std::fs::write(
                    sc_dir.join(format!("stderr.attempt{attempt}.log")),
                    &raw.stderr,
                )?;
            }
            last_raw = Some(raw);
            if pass {
                break;
            }
        }

        let raw = last_raw.ok_or_else(|| TcError::InvalidState("no test attempts".into()))?;
        write_phase(
            &sc_dir,
            "test",
            raw.exit_code == Some(0) && !raw.timed_out,
            raw.exit_code,
            raw.timed_out,
            raw.duration_ms,
            "none",
            &env.image,
            env.image_digest.clone(),
            &test_commands,
            "test complete",
        )?;
        std::fs::write(
            sc_dir.join("test-result.json"),
            serde_json::to_string_pretty(&fr_json(&raw, Utc::now()))?,
        )?;

        let verdict = if scenario.is_baseline {
            if attempt_pass.iter().any(|p| *p) {
                baseline_ok = true;
                Verdict::BaselinePass
            } else {
                baseline_ok = false;
                Verdict::BaselineInvalid
            }
        } else {
            classify_from_reruns(&attempt_pass)
        };

        let failure = if !matches!(verdict, Verdict::BaselinePass | Verdict::FuturePass) {
            Some(adapter.normalize_failure(&raw))
        } else {
            None
        };

        let mut all_cmds = fetch_cmds.clone().unwrap_or_default();
        all_cmds.extend(test_commands.clone());

        let exec = ExecutionResult {
            scenario_id: scenario.id.clone(),
            attempt: attempt_pass.len() as u32,
            verdict,
            exit_code: raw.exit_code,
            duration_ms: raw.duration_ms,
            timed_out: raw.timed_out,
            failure: failure.clone(),
            environment: env.clone(),
            commands: all_cmds,
        };

        persist_scenario_artifacts(
            &sc_dir,
            scenario,
            &env,
            fetch_cmds.as_deref().unwrap_or(&[]),
            &test_commands,
            fetch_raw.as_ref(),
            Some(&raw),
            &exec,
            executor.engine_label(),
            failure.as_ref(),
        )?;

        ordered_for_frontier.push((scenario.clone(), exec.clone()));
        results.push(exec);

        if matches!(verdict, Verdict::FutureFail) && first_fail_scenario.is_none() {
            first_fail_scenario = Some(scenario.id.clone());
            confirmed_first_fail = attempt_pass.iter().all(|p| !*p) && !attempt_pass.is_empty();
        }

        if matches!(verdict, Verdict::BaselineInvalid) {
            break;
        }
    }

    // ddmin note only — not acceptance evidence
    let mut frontier_notes = Vec::new();
    if let Some(combo) = results
        .iter()
        .find(|r| r.scenario_id.starts_with("combo-") && matches!(r.verdict, Verdict::FutureFail))
    {
        let axes = ordered_for_frontier
            .iter()
            .find(|(s, _)| s.id == combo.scenario_id)
            .map(|(s, _)| s.axes_changed.clone())
            .unwrap_or_default();
        let minimal = ddmin_axes(&axes, |subset| {
            subset.iter().any(|ax| {
                results.iter().any(|r| {
                    let sc = plan.scenarios.iter().find(|s| s.id == r.scenario_id);
                    sc.map(|s| {
                        s.axes_changed == vec![*ax] && matches!(r.verdict, Verdict::FutureFail)
                    })
                    .unwrap_or(false)
                })
            })
        });
        frontier_notes.push(format!(
            "ddmin label summary (NOT live reduction execution): {minimal:?}"
        ));
        layout.write_json(
            "reduction.json",
            &serde_json::json!({
                "combo": combo.scenario_id,
                "minimal_axes": minimal,
                "note": "NOT_RUN as real ddmin execution — label summary only",
            }),
        )?;
    }

    let replay_cmd = first_fail_scenario
        .as_ref()
        .map(|s| format!("tomorrowci replay {run_id} --scenario {s}"));

    let mut frontier = compute_breakage_frontier(
        baseline_ok,
        &ordered_for_frontier,
        confirmed_first_fail,
        replay_cmd.clone(),
    );
    frontier.notes.extend(frontier_notes);
    if is_scripted {
        frontier
            .notes
            .push("executor=scripted — NOT acceptance evidence for live adapter".into());
    }

    layout.write_json("verdicts.json", &results)?;
    layout.write_json("frontier.json", &frontier)?;

    let run_finished = Utc::now();
    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at: run_started,
        finished_at: Some(run_finished),
        repository: RepositorySnapshot {
            source: repo.display().to_string(),
            path: repo.to_path_buf(),
            commit_sha: git_head(repo),
            is_disposable_copy: true,
        },
        config_hash: config.content_hash()?,
        detection,
        baseline,
        plan,
        results: results.clone(),
        frontier: frontier.clone(),
        evidence_root: layout.run_root.clone(),
    };
    write_run_manifest(&layout, &manifest)?;
    write_json_report(&manifest, &layout.run_root.join("report.json"))?;
    write_html_report(&manifest, &layout.run_root.join("report.html"))?;
    write_github_job_summary(&manifest, &layout.run_root.join("job-summary.md"))?;

    // Run-level checksums for required files
    let mut run_checksums = Vec::new();
    for name in [
        "run.json",
        "plan.json",
        "verdicts.json",
        "frontier.json",
        "report.html",
        "job-summary.md",
        "metrics.json",
    ] {
        let p = layout.run_root.join(name);
        if p.exists() {
            if let Ok(h) = tomorrowci_evidence::file_checksum(&p) {
                run_checksums.push((name.into(), h));
            }
        }
    }
    write_checksums(&layout.run_root, &run_checksums)?;

    let metrics =
        ScanMetrics::from_manifest(&manifest, Some(wall_start.elapsed().as_millis() as u64));
    metrics.write_json(&layout.run_root.join("metrics.json"))?;
    // refresh metrics checksum
    if let Ok(h) = tomorrowci_evidence::file_checksum(&layout.run_root.join("metrics.json")) {
        run_checksums.retain(|(n, _)| n != "metrics.json");
        run_checksums.push(("metrics.json".into(), h));
        write_checksums(&layout.run_root, &run_checksums)?;
    }

    let mut terminal_summary = render_terminal_summary(&manifest);
    terminal_summary.push_str(&metrics.summary_line());
    terminal_summary.push('\n');
    std::fs::write(layout.run_root.join("summary.txt"), &terminal_summary)?;

    Ok(ScanOutcome {
        manifest,
        evidence_root: layout.run_root,
        terminal_summary,
        metrics,
    })
}

/// Test-only scan with injected executor (scripted).
pub fn scan_with_executor(
    repo: &Path,
    adapter: &dyn EcosystemAdapter,
    config: Config,
    executor: &dyn ScenarioExecutor,
    detection: ProjectDetection,
) -> Result<ScanOutcome> {
    let wall_start = Instant::now();
    let run_started = Utc::now();
    let run_id = format!("test{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
    let layout = EvidenceLayout::create(repo, &run_id)?;
    let work = layout.run_root.join("workspace");
    make_disposable_copy(repo, &work)?;
    prepare_scenario_state(&work)?;

    let baseline = adapter.baseline(repo, &config)?;
    let rt_cands = adapter.candidates(&baseline, &config)?;
    let dep_cands = dependency_candidates(&baseline, &config);
    let (plan, _) = plan_scenarios(&baseline, &rt_cands, &dep_cands, &config);
    layout.write_json("plan.json", &plan)?;

    let mut results = Vec::new();
    let mut ordered = Vec::new();
    let mut baseline_ok = false;
    let mut confirmed_first_fail = false;
    let mut first_fail = None;
    let eco = detection.ecosystem;

    for scenario in &plan.scenarios {
        let mut env = adapter.materialize(scenario, &work)?;
        env.image = normalize_image(eco, &scenario.runtime);
        env.image_digest = Some(executor.ensure_image(&env.image)?);
        let commands = build_scenario_commands(adapter, scenario, &config, &work)?;
        let fetch_cmds = build_fetch_commands(eco, scenario, &work, true)
            .ok()
            .flatten();
        let sc_dir = layout.ensure_scenario(&scenario.id)?;

        if let Some(ref fcmds) = fetch_cmds {
            let _ = executor.execute(&ExecutionContext {
                workspace: &work,
                scenario,
                environment: &env,
                commands: fcmds,
                timeout: Duration::from_secs(30),
                network: "bridge",
            })?;
        }

        let reruns = if scenario.is_baseline {
            1
        } else {
            config.execution.reruns_on_failure.max(1)
        };
        let mut attempts = Vec::new();
        let mut last_raw = None;
        for _ in 0..reruns {
            let raw = executor.execute(&ExecutionContext {
                workspace: &work,
                scenario,
                environment: &env,
                commands: &commands,
                timeout: Duration::from_secs(30),
                network: "none",
            })?;
            attempts.push(raw.exit_code == Some(0) && !raw.timed_out);
            last_raw = Some(raw);
            if *attempts.last().unwrap_or(&false) {
                break;
            }
        }
        let raw = last_raw.unwrap();
        let verdict = if scenario.is_baseline {
            if attempts.iter().any(|p| *p) {
                baseline_ok = true;
                Verdict::BaselinePass
            } else {
                Verdict::BaselineInvalid
            }
        } else {
            classify_from_reruns(&attempts)
        };
        let failure = if !verdict.is_pass_like() {
            Some(adapter.normalize_failure(&raw))
        } else {
            None
        };
        let exec = ExecutionResult {
            scenario_id: scenario.id.clone(),
            attempt: attempts.len() as u32,
            verdict,
            exit_code: raw.exit_code,
            duration_ms: raw.duration_ms,
            timed_out: raw.timed_out,
            failure,
            environment: env,
            commands,
        };
        std::fs::write(
            sc_dir.join("result.json"),
            serde_json::to_string_pretty(&exec)?,
        )?;
        if matches!(verdict, Verdict::FutureFail) && first_fail.is_none() {
            first_fail = Some(scenario.id.clone());
            confirmed_first_fail = attempts.iter().all(|p| !*p);
        }
        ordered.push((scenario.clone(), exec.clone()));
        results.push(exec);
        if matches!(verdict, Verdict::BaselineInvalid) {
            break;
        }
    }

    let frontier = compute_breakage_frontier(
        baseline_ok,
        &ordered,
        confirmed_first_fail,
        first_fail
            .as_ref()
            .map(|s| format!("tomorrowci replay {run_id} --scenario {s}")),
    );

    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at: run_started,
        finished_at: Some(Utc::now()),
        repository: RepositorySnapshot {
            source: repo.display().to_string(),
            path: repo.to_path_buf(),
            commit_sha: git_head(repo),
            is_disposable_copy: true,
        },
        config_hash: config.content_hash()?,
        detection,
        baseline,
        plan,
        results,
        frontier,
        evidence_root: layout.run_root.clone(),
    };
    write_run_manifest(&layout, &manifest)?;
    write_html_report(&manifest, &layout.run_root.join("report.html"))?;
    write_github_job_summary(&manifest, &layout.run_root.join("job-summary.md"))?;
    let metrics =
        ScanMetrics::from_manifest(&manifest, Some(wall_start.elapsed().as_millis() as u64));
    metrics.write_json(&layout.run_root.join("metrics.json"))?;
    let mut terminal_summary = render_terminal_summary(&manifest);
    terminal_summary.push_str(&metrics.summary_line());
    terminal_summary.push('\n');
    Ok(ScanOutcome {
        manifest,
        evidence_root: layout.run_root,
        terminal_summary,
        metrics,
    })
}

fn dependency_candidates(baseline: &Baseline, config: &Config) -> Vec<tomorrowci_core::Candidate> {
    let mut out = Vec::new();
    if config.candidates.dependencies.latest_allowed {
        out.push(tomorrowci_core::Candidate {
            id: "deps-latest-allowed".into(),
            axis: EnvironmentAxis::Dependencies,
            label: format!("{} + latest allowed dependencies", baseline.runtime),
            version: "latest-allowed".into(),
            channel: "stable".into(),
            grade_if_executed: EvidenceGrade::Simulated,
            order_key: "0001".into(),
        });
    }
    if config.candidates.dependencies.prerelease {
        out.push(tomorrowci_core::Candidate {
            id: "deps-prerelease".into(),
            axis: EnvironmentAxis::Dependencies,
            label: "prerelease dependencies".into(),
            version: "prerelease".into(),
            channel: "preview".into(),
            grade_if_executed: EvidenceGrade::Simulated,
            order_key: "0002".into(),
        });
    }
    out
}

fn normalize_image(eco: Ecosystem, runtime: &str) -> String {
    match eco {
        Ecosystem::Python => {
            if runtime.contains("python:") {
                if runtime.contains('-') {
                    runtime.to_string()
                } else {
                    format!("{runtime}-slim")
                }
            } else if runtime
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                format!("python:{runtime}-slim")
            } else {
                format!("python:{runtime}")
            }
        }
        Ecosystem::Node => {
            if runtime.starts_with("node:") {
                runtime.to_string()
            } else {
                format!("node:{}", runtime.trim_start_matches("node:"))
            }
        }
        Ecosystem::Rust => {
            if runtime.starts_with("rust:") {
                runtime.to_string()
            } else {
                format!("rust:{runtime}-bookworm")
            }
        }
        Ecosystem::Unknown => runtime.to_string(),
    }
}

fn build_fetch_commands(
    eco: Ecosystem,
    scenario: &Scenario,
    work: &Path,
    scripted: bool,
) -> Result<Option<Vec<CommandSpec>>> {
    let upgrade =
        scenario.dependencies == "latest-allowed" || scenario.dependencies == "prerelease";
    match eco {
        Ecosystem::Python => {
            if scripted {
                // Keep scripted harness free of host filesystem requirements for venv paths
                return Ok(Some(vec![CommandSpec {
                    argv: vec!["true".into()],
                    cwd: Some("/work".into()),
                    network: true,
                    phase: "fetch".into(),
                }]));
            }
            Ok(Some(python_fetch_commands(work, upgrade)?))
        }
        Ecosystem::Node => {
            let argv: Vec<String> = if upgrade {
                vec![
                    "npm".into(),
                    "install".into(),
                    "--no-audit".into(),
                    "--no-fund".into(),
                ]
            } else {
                vec![
                    "sh".into(),
                    "-c".into(),
                    "if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi".into(),
                ]
            };
            Ok(Some(vec![CommandSpec {
                argv,
                cwd: Some("/work".into()),
                network: true,
                phase: "fetch".into(),
            }]))
        }
        Ecosystem::Rust => Ok(Some(vec![CommandSpec {
            argv: vec!["cargo".into(), "fetch".into()],
            cwd: Some("/work".into()),
            network: true,
            phase: "fetch".into(),
        }])),
        Ecosystem::Unknown => Ok(None),
    }
}

fn build_scenario_commands(
    adapter: &dyn EcosystemAdapter,
    scenario: &Scenario,
    config: &Config,
    _work: &Path,
) -> Result<Vec<CommandSpec>> {
    adapter.commands(scenario, config)
}

fn blocked_result(
    scenario: &Scenario,
    env: &EnvironmentSpec,
    commands: &[CommandSpec],
    detail: &str,
) -> ExecutionResult {
    ExecutionResult {
        scenario_id: scenario.id.clone(),
        attempt: 0,
        verdict: Verdict::Blocked,
        exit_code: None,
        duration_ms: 0,
        timed_out: false,
        failure: Some(FailureSignature {
            kind: "Blocked".into(),
            summary: detail.chars().take(200).collect(),
            normalized_hash: tomorrowci_core::sha256_str(detail),
            primary_frame: None,
        }),
        environment: env.clone(),
        commands: commands.to_vec(),
    }
}

fn layout_write_scenario_meta(
    sc_dir: &Path,
    scenario: &Scenario,
    env: &EnvironmentSpec,
    commands: &[CommandSpec],
) -> Result<()> {
    std::fs::write(
        sc_dir.join("scenario.json"),
        serde_json::to_string_pretty(scenario)?,
    )?;
    std::fs::write(
        sc_dir.join("environment.json"),
        serde_json::to_string_pretty(env)?,
    )?;
    std::fs::write(
        sc_dir.join("commands.json"),
        serde_json::to_string_pretty(commands)?,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_phase(
    sc_dir: &Path,
    phase: &str,
    ok: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    network: &str,
    image: &str,
    image_digest: Option<String>,
    commands: &[CommandSpec],
    detail: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let pr = PhaseResult {
        phase: phase.into(),
        ok,
        exit_code,
        timed_out,
        duration_ms,
        network: network.into(),
        image: image.into(),
        image_digest,
        argv: commands.iter().map(|c| c.argv.clone()).collect(),
        started_at: now.clone(),
        finished_at: now,
        detail: detail.into(),
    };
    std::fs::write(
        sc_dir.join(format!("{phase}-phase.json")),
        serde_json::to_string_pretty(&pr)?,
    )?;
    Ok(())
}

fn write_raw_logs(sc_dir: &Path, prefix: &str, raw: &RawExecutionResult) -> Result<()> {
    std::fs::write(sc_dir.join(format!("{prefix}-stdout.log")), &raw.stdout)?;
    std::fs::write(sc_dir.join(format!("{prefix}-stderr.log")), &raw.stderr)?;
    Ok(())
}

fn fr_json(raw: &RawExecutionResult, started: chrono::DateTime<Utc>) -> serde_json::Value {
    serde_json::json!({
        "exit_code": raw.exit_code,
        "timed_out": raw.timed_out,
        "duration_ms": raw.duration_ms,
        "network_used": raw.network_used,
        "started_at": started.to_rfc3339(),
        "finished_at": Utc::now().to_rfc3339(),
    })
}

fn artifact_count(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|rd| rd.count()).unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn persist_scenario_artifacts(
    sc_dir: &Path,
    scenario: &Scenario,
    env: &EnvironmentSpec,
    fetch_cmds: &[CommandSpec],
    test_cmds: &[CommandSpec],
    fetch_raw: Option<&RawExecutionResult>,
    test_raw: Option<&RawExecutionResult>,
    exec: &ExecutionResult,
    engine: String,
    failure: Option<&FailureSignature>,
) -> Result<()> {
    layout_write_scenario_meta(sc_dir, scenario, env, test_cmds)?;
    std::fs::write(
        sc_dir.join("result.json"),
        serde_json::to_string_pretty(exec)?,
    )?;
    if let Some(raw) = test_raw {
        std::fs::write(sc_dir.join("stdout.log"), &raw.stdout)?;
        std::fs::write(sc_dir.join("stderr.log"), &raw.stderr)?;
    }
    if let Some(f) = failure {
        std::fs::write(
            sc_dir.join("failure-signature.json"),
            serde_json::to_string_pretty(f)?,
        )?;
    }
    let replay = serde_json::json!({
        "scenario_id": scenario.id,
        "engine": engine,
        "image": env.image,
        "image_digest": env.image_digest,
        "workdir": env.workdir,
        "user": env.user,
        "memory_mb": env.memory_mb,
        "cpus": env.cpus,
        "pids_limit": env.pids_limit,
        "read_only_root": env.read_only_root,
        "fetch_network": "bridge",
        "test_network": "none",
        "fetch_argv": fetch_cmds.iter().map(|c| c.argv.clone()).collect::<Vec<_>>(),
        "test_argv": test_cmds.iter().map(|c| c.argv.clone()).collect::<Vec<_>>(),
        "expected_exit_code": exec.exit_code,
        "expected_failure_signature": failure,
    });
    std::fs::write(
        sc_dir.join("replay.json"),
        serde_json::to_string_pretty(&replay)?,
    )?;
    write_replay_scripts(sc_dir, env, fetch_cmds, test_cmds, &scenario.id, &engine)?;

    let mut checksums = Vec::new();
    for name in [
        "scenario.json",
        "environment.json",
        "fetch-commands.json",
        "test-commands.json",
        "commands.json",
        "result.json",
        "stdout.log",
        "stderr.log",
        "failure-signature.json",
        "replay.json",
        "replay.sh",
        "replay.ps1",
        "fetch-result.json",
        "test-result.json",
    ] {
        let p = sc_dir.join(name);
        if p.exists() {
            if let Ok(h) = tomorrowci_evidence::file_checksum(&p) {
                checksums.push((name.into(), h));
            }
        }
    }
    if let Some(raw) = fetch_raw {
        let _ = raw; // already on disk if written
    }
    write_checksums(sc_dir, &checksums)?;
    Ok(())
}

fn write_replay_scripts(
    sc_dir: &Path,
    env: &EnvironmentSpec,
    fetch_cmds: &[CommandSpec],
    test_cmds: &[CommandSpec],
    scenario_id: &str,
    engine: &str,
) -> Result<()> {
    let bin = if engine == "podman" {
        "podman"
    } else {
        "docker"
    };
    let image = env
        .image_digest
        .clone()
        .filter(|d| d.contains("sha256:") || d.starts_with("sha256:"))
        .unwrap_or_else(|| env.image.clone());
    let user = env
        .user
        .as_ref()
        .map(|u| format!(" --user {u}"))
        .unwrap_or_default();
    let fetch = fetch_cmds
        .iter()
        .map(|c| shell_join(&c.argv))
        .collect::<Vec<_>>()
        .join(" && ");
    let test = test_cmds
        .iter()
        .map(|c| shell_join(&c.argv))
        .collect::<Vec<_>>()
        .join(" && ");
    let mem = env.memory_mb;
    let cpus = env.cpus;
    let pids = env.pids_limit;
    let ro = if env.read_only_root {
        " --read-only --tmpfs /tmp:rw,exec,nosuid,size=256m"
    } else {
        ""
    };
    let sh = format!(
        r#"#!/usr/bin/env bash
# Replay scenario {scenario_id} — digest-pinned; workspace must be recorded copy
set -euo pipefail
IMG={image:?}
WORK="${{TOMORROWCI_WORKSPACE:-$PWD}}"
{bin} run --rm --network bridge --memory {mem}m --cpus {cpus} --pids-limit {pids} \
  --security-opt no-new-privileges --cap-drop ALL{user}{ro} \
  -v "$WORK":/work -w /work "$IMG" sh -c {fetch:?}
{bin} run --rm --network none --memory {mem}m --cpus {cpus} --pids-limit {pids} \
  --security-opt no-new-privileges --cap-drop ALL{user}{ro} \
  -v "$WORK":/work -w /work "$IMG" sh -c {test:?}
"#
    );
    std::fs::write(sc_dir.join("replay.sh"), sh)?;
    let ps1 = format!(
        r#"# Replay scenario {scenario_id}
$Img = {image:?}
$Work = if ($env:TOMORROWCI_WORKSPACE) {{ $env:TOMORROWCI_WORKSPACE }} else {{ $PWD }}
{bin} run --rm --network bridge --memory {mem}m --cpus {cpus} --pids-limit {pids} --security-opt no-new-privileges --cap-drop ALL{user}{ro} -v "${{Work}}:/work" -w /work $Img sh -c {fetch:?}
{bin} run --rm --network none --memory {mem}m --cpus {cpus} --pids-limit {pids} --security-opt no-new-privileges --cap-drop ALL{user}{ro} -v "${{Work}}:/work" -w /work $Img sh -c {test:?}
"#
    );
    std::fs::write(sc_dir.join("replay.ps1"), ps1)?;
    Ok(())
}

fn git_head(repo: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

pub fn render_terminal_summary(m: &RunManifest) -> String {
    let mut out = String::new();
    out.push_str(&format!("TomorrowCI run {}\n", m.run_id));
    out.push_str(&format!(
        "Repository: {} @ {}\n",
        m.repository.source,
        m.repository.commit_sha.as_deref().unwrap_or("unknown")
    ));
    for r in &m.results {
        let sc = m.plan.scenarios.iter().find(|s| s.id == r.scenario_id);
        let label = sc
            .map(|s| {
                let eco = format!("{:?}", m.detection.ecosystem);
                if s.is_baseline {
                    format!("Baseline: {} + {}", s.runtime, s.dependencies)
                } else {
                    format!("{eco} {} + {} deps", s.runtime, s.dependencies)
                }
            })
            .unwrap_or_else(|| r.scenario_id.clone());
        let v = match r.verdict {
            Verdict::BaselinePass | Verdict::FuturePass => "PASS",
            Verdict::BaselineInvalid | Verdict::FutureFail => "FAIL",
            Verdict::Flaky => "FLAKY",
            Verdict::Blocked => "BLOCKED",
            Verdict::Unsupported => "UNSUPPORTED",
            Verdict::Inconclusive => "INCONCLUSIVE",
        };
        out.push_str(&format!("{label:-50} {v}\n"));
        if let Some(ref d) = r.environment.image_digest {
            out.push_str(&format!("  digest: {d}\n"));
        }
    }
    out.push('\n');
    if m.frontier.observed {
        out.push_str(&format!(
            "Observed breakage horizon: {}\n",
            m.frontier.horizon_label.as_deref().unwrap_or("?")
        ));
        out.push_str(&format!(
            "Minimal changed axis: {:?}\n",
            m.frontier.changed_axes
        ));
        if let Some(ref sig) = m.frontier.failure_signature {
            out.push_str(&format!(
                "Stable failure signature: {} — {}\n",
                sig.kind, sig.summary
            ));
        }
        if let Some(ref cmd) = m.frontier.replay_command {
            out.push_str(&format!("Reproduce: {cmd}\n"));
        }
    } else {
        out.push_str("No observed breakage horizon within tested candidates.\n");
        for n in &m.frontier.notes {
            out.push_str(&format!("note: {n}\n"));
        }
    }
    out.push_str(&format!("Evidence: {}\n", m.evidence_root.display()));
    out.push_str(&format!("Evidence grade: {:?}\n", m.frontier.grade));
    out
}

pub fn load_and_explain(repo: &Path, run_id: &str) -> Result<String> {
    let root = repo.join(".tomorrowci/runs").join(run_id);
    let m = tomorrowci_evidence::load_run_manifest(&root)?;
    Ok(render_terminal_summary(&m))
}

/// Exact replay: recorded digest, fetch+test, compare exit + failure signature.
pub fn replay_scenario(repo: &Path, run_id: &str, scenario_id: &str) -> Result<String> {
    let root = repo.join(".tomorrowci/runs").join(run_id);
    let m = tomorrowci_evidence::load_run_manifest(&root)?;
    let sc_dir = root.join("scenarios").join(scenario_id);
    if !sc_dir.join("result.json").exists() {
        return Err(TcError::Blocked(format!(
            "scenario evidence missing for {scenario_id}"
        )));
    }

    let original: ExecutionResult =
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("result.json"))?)?;
    let env: EnvironmentSpec =
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("environment.json"))?)?;
    let fetch_cmds: Vec<CommandSpec> = if sc_dir.join("fetch-commands.json").exists() {
        serde_json::from_str(&std::fs::read_to_string(
            sc_dir.join("fetch-commands.json"),
        )?)?
    } else {
        Vec::new()
    };
    let test_cmds: Vec<CommandSpec> = if sc_dir.join("test-commands.json").exists() {
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("test-commands.json"))?)?
    } else {
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("commands.json"))?)?
    };
    let scenario = m
        .plan
        .scenarios
        .iter()
        .find(|s| s.id == scenario_id)
        .cloned()
        .ok_or_else(|| TcError::Other("scenario not in manifest".into()))?;

    let recorded_digest = env.image_digest.clone().ok_or_else(|| {
        TcError::Blocked("recorded image digest missing; cannot exact-replay".into())
    })?;

    let work = root.join("workspace");
    if !work.exists() {
        return Err(TcError::Blocked(
            "workspace snapshot missing for replay; external artifact unavailable".into(),
        ));
    }

    let executor = ContainerExecutor::detect()?;
    // Resolve and require same digest
    let resolved = executor.ensure_image(
        if recorded_digest.contains('@') || recorded_digest.starts_with("sha256:") {
            &recorded_digest
        } else {
            &env.image
        },
    )?;
    let norm = |d: &str| {
        d.split("sha256:")
            .nth(1)
            .unwrap_or(d)
            .chars()
            .take(64)
            .collect::<String>()
    };
    if norm(&resolved) != norm(&recorded_digest) && resolved != recorded_digest {
        return Err(TcError::Blocked(format!(
            "image digest changed: recorded={recorded_digest} resolved={resolved}"
        )));
    }

    let mut env_run = env.clone();
    env_run.image_digest = Some(recorded_digest.clone());
    if recorded_digest.contains('@') {
        env_run.image = recorded_digest.clone();
    }

    // Re-prepare venv paths (fetch will recreate)
    prepare_scenario_state(&work)?;

    if !fetch_cmds.is_empty() {
        let fr = executor.execute(&ExecutionContext {
            workspace: &work,
            scenario: &scenario,
            environment: &env_run,
            commands: &fetch_cmds,
            timeout: Duration::from_secs(600),
            network: "bridge",
        })?;
        if fr.exit_code != Some(0) || fr.timed_out {
            return Err(TcError::Blocked(format!(
                "replay fetch failed exit={:?}",
                fr.exit_code
            )));
        }
    }

    let raw = executor.execute(&ExecutionContext {
        workspace: &work,
        scenario: &scenario,
        environment: &env_run,
        commands: &test_cmds,
        timeout: Duration::from_secs(900),
        network: "none",
    })?;

    let adapter = PythonAdapter;
    let new_sig = if raw.exit_code != Some(0) {
        Some(adapter.normalize_failure(&raw))
    } else {
        None
    };

    let exit_match = raw.exit_code == original.exit_code && raw.timed_out == original.timed_out;
    let sig_match = match (&original.failure, &new_sig) {
        (Some(a), Some(b)) => a.normalized_hash == b.normalized_hash,
        (None, None) => true,
        _ => false,
    };

    let ok = exit_match && sig_match;
    let report = serde_json::json!({
        "scenario_id": scenario_id,
        "ok": ok,
        "original_exit": original.exit_code,
        "replay_exit": raw.exit_code,
        "original_signature": original.failure.as_ref().map(|f| &f.normalized_hash),
        "replay_signature": new_sig.as_ref().map(|f| &f.normalized_hash),
        "recorded_digest": recorded_digest,
        "resolved_digest": resolved,
    });
    std::fs::write(
        sc_dir.join("replay-result.json"),
        serde_json::to_string_pretty(&report)?,
    )?;

    let mut out = format!(
        "replay {scenario_id}: exit={:?} timed_out={} duration_ms={}\n",
        raw.exit_code, raw.timed_out, raw.duration_ms
    );
    out.push_str(&format!(
        "original_exit={:?} signature_match={sig_match} exit_match={exit_match}\n",
        original.exit_code
    ));
    if let Some(ref s) = new_sig {
        out.push_str(&format!("replay_signature={}\n", s.normalized_hash));
    }
    if let Some(ref s) = original.failure {
        out.push_str(&format!("original_signature={}\n", s.normalized_hash));
    }
    if !ok {
        return Err(TcError::Other(format!(
            "replay divergence for {scenario_id}: exit_match={exit_match} sig_match={sig_match}"
        )));
    }
    out.push_str("replay: PASS (exit + failure signature match)\n");
    Ok(out)
}
