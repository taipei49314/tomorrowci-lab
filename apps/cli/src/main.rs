//! TomorrowCI CLI — Continuous Integration Against the Future.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tomorrowci_adapter_node::NodeAdapter;
use tomorrowci_adapter_python::PythonAdapter;
use tomorrowci_adapter_rust::RustAdapter;
use tomorrowci_adapters::EcosystemAdapter;
use tomorrowci_core::{compare_horizons, evaluate_policy_gate, Config, HorizonDelta, Verdict};
use tomorrowci_evidence::{
    finalize_run_checksums, find_run_dir, load_run_manifest, verify_run_root,
    write_verification_attestation,
};
use tomorrowci_metrics::{run_trust_audit, ClaimLedger, ClaimStatus, ScanMetrics, TrustVerdict};
use tomorrowci_report::{
    write_github_job_summary, write_html_report, write_json_report, write_sarif_stub,
};
use tomorrowci_runner::{load_and_explain, replay_scenario, scan_local, ScanOptions};
use tomorrowci_sandbox::{detect_engines, SecurityPolicy};

#[derive(Parser, Debug)]
#[command(
    name = "tomorrowci",
    version,
    about = "Continuous Integration Against the Future."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a repository path (Python/Node/Rust)
    Scan {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Emit machine-readable scan result JSON on stdout (last line still human-friendly fields included)
        #[arg(long)]
        json: bool,
    },
    Show {
        run_id: String,
    },
    /// Verify evidence integrity for a run
    Verify {
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    Replay {
        run_id: String,
        #[arg(long)]
        scenario: String,
    },
    Explain {
        run_id: String,
    },
    Report {
        run_id: String,
        #[arg(long, default_value = "json")]
        format: String,
    },
    Doctor,
    /// Trust-behavior audit (security invariants — no target code execution)
    Trust {
        #[arg(long)]
        json: bool,
    },
    /// Compare base vs head run frontiers (PR horizon delta)
    Compare {
        #[arg(long)]
        base: String,
        #[arg(long)]
        head: String,
        #[arg(long)]
        gate: bool,
    },
    /// Print metrics.json for a run
    Metrics {
        run_id: String,
    },
    #[command(name = "init-action")]
    InitAction {
        #[arg(long, default_value = ".github/workflows/tomorrowci.yml")]
        out: PathBuf,
    },
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => cmd_doctor(),
        Commands::Trust { json } => cmd_trust(json),
        Commands::Scan {
            target,
            config,
            json,
        } => cmd_scan(&target, config.as_deref(), json),
        Commands::Show { run_id } => cmd_show(&run_id),
        Commands::Verify { run_id, json } => cmd_verify(&run_id, json),
        Commands::Replay { run_id, scenario } => {
            let cwd = std::env::current_dir()?;
            // Prefer run under cwd; also resolve fixture-local runs
            let root = find_run_dir(&cwd, &run_id);
            let repo = root
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .unwrap_or(&cwd);
            print!("{}", replay_scenario(repo, &run_id, &scenario)?);
            Ok(())
        }
        Commands::Explain { run_id } => {
            let cwd = std::env::current_dir()?;
            print!("{}", load_and_explain(&cwd, &run_id)?);
            Ok(())
        }
        Commands::Report { run_id, format } => cmd_report(&run_id, &format),
        Commands::Compare { base, head, gate } => cmd_compare(&base, &head, gate),
        Commands::Metrics { run_id } => cmd_metrics(&run_id),
        Commands::InitAction { out } => cmd_init_action(&out),
    }
}

fn cmd_doctor() -> Result<()> {
    println!("TomorrowCI doctor");
    println!("tool_version: {}", env!("CARGO_PKG_VERSION"));
    let engines = detect_engines();
    println!("docker: {}", engines.docker);
    println!("podman: {}", engines.podman);
    println!(
        "selected_engine: {}",
        engines
            .selected
            .map(|e| format!("{e:?}"))
            .unwrap_or_else(|| "NONE (sandbox BLOCKED)".into())
    );
    for n in &engines.notes {
        println!("note: {n}");
    }
    SecurityPolicy::default()
        .validate_safe_defaults()
        .context("security policy")?;
    println!("security_defaults: OK");
    println!("host_execution_of_targets: FORBIDDEN by default");
    println!(
        "status: {}",
        if engines.selected.is_some() {
            "READY"
        } else {
            "BLOCKED for container execution"
        }
    );
    Ok(())
}

fn cmd_trust(json: bool) -> Result<()> {
    let report = run_trust_audit()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("TomorrowCI trust audit");
        println!("overall: {:?}", report.overall);
        for p in &report.probes {
            println!("[{:?}] {} — {}", p.verdict, p.id, p.title);
            println!("         {}", p.detail);
        }
        if report.overall == TrustVerdict::Fail {
            bail!("trust audit FAILED");
        }
        println!("status: PASS (Blocked probes are infra-only, not trust failures)");
    }
    if report.failed() {
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_scan(target: &str, config_path: Option<&Path>, json: bool) -> Result<()> {
    if target.starts_with("http://") || target.starts_with("https://") {
        bail!("remote GitHub clone scan: NOT_RUN in this build (local path only)");
    }
    let root = PathBuf::from(target);
    if !root.exists() {
        bail!("path does not exist: {}", root.display());
    }
    let cfg = load_config(&root, config_path)?;

    let py = PythonAdapter.detect(&root);
    let node = NodeAdapter.detect(&root);
    let rust = RustAdapter.detect(&root);
    let eco = if py.supported {
        "python"
    } else if node.supported {
        "node"
    } else if rust.supported {
        "rust"
    } else {
        println!("verdict: UNSUPPORTED");
        return Ok(());
    };
    println!("ecosystem: {eco}");
    println!("detection: PASS");

    match scan_local(
        &root,
        ScanOptions {
            config: cfg,
            allow_scripted: false,
        },
    ) {
        Ok(out) => {
            println!("{}", out.terminal_summary);
            println!(
                "report: {}",
                out.evidence_root.join("report.html").display()
            );
            println!(
                "metrics: {}",
                out.evidence_root.join("metrics.json").display()
            );
            let mut claims = ClaimLedger::default();
            let any_blocked = out
                .manifest
                .results
                .iter()
                .any(|r| matches!(r.verdict, Verdict::Blocked));
            let status = if any_blocked {
                ClaimStatus::Blocked
            } else {
                ClaimStatus::Pass
            };
            claims.push(
                format!("{eco} scan completed"),
                status,
                format!("tomorrowci scan {}", root.display()),
                out.metrics.summary_line(),
                out.evidence_root.display().to_string(),
            );
            claims.write_json(&out.evidence_root.join("claims.json"))?;
            // Re-finalize inventory after claims.json is written
            finalize_run_checksums(&out.evidence_root)?;
            let run_id = out.manifest.run_id.clone();
            println!("run_id: {run_id}");
            if json {
                let payload = serde_json::json!({
                    "run_id": run_id,
                    "evidence_root": out.evidence_root,
                    "frontier_observed": out.manifest.frontier.observed,
                    "first_failing_scenario": out.manifest.frontier.first_failing_scenario,
                    "source_commit": out.manifest.repository.commit_sha,
                    "tool_version": out.manifest.tool_version,
                    "blocked": any_blocked,
                });
                println!("{}", serde_json::to_string(&payload)?);
            }
            // Never promote BLOCKED to success: non-zero exit for infra/construction blocks
            if any_blocked {
                println!("verdict: BLOCKED");
                std::process::exit(2);
            }
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("BLOCKED")
                || msg.contains("blocked:")
                || msg.contains("sandbox")
                || msg.contains("Docker")
                || msg.contains("Podman")
                || msg.contains("daemon")
            {
                println!("verdict: BLOCKED");
                println!("{msg}");
                std::process::exit(2);
            } else if msg.contains("UNSUPPORTED") || msg.contains("unsupported:") {
                println!("verdict: UNSUPPORTED");
                println!("{msg}");
                std::process::exit(3);
            } else {
                Err(e.into())
            }
        }
    }
}

fn load_config(root: &Path, config_path: Option<&Path>) -> Result<Config> {
    if let Some(p) = config_path {
        Ok(Config::load_file(p)?)
    } else if root.join(".tomorrowci.yml").exists() {
        Ok(Config::load_file(&root.join(".tomorrowci.yml"))?)
    } else {
        Ok(Config::default())
    }
}

fn cmd_show(run_id: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = find_run_dir(&cwd, run_id);
    let m = load_run_manifest(&root)?;
    println!("run: {}", m.run_id);
    for r in &m.results {
        println!("  {} => {:?}", r.scenario_id, r.verdict);
    }
    println!("frontier.observed: {}", m.frontier.observed);
    Ok(())
}

fn cmd_verify(run_id: &str, json: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = find_run_dir(&cwd, run_id);
    let rep = verify_run_root(&root)?;
    // Attestation write is required; failure must prevent PASS (G1).
    if let Err(e) = write_verification_attestation(&root, &rep, env!("CARGO_PKG_VERSION")) {
        if json {
            println!("{}", serde_json::to_string_pretty(&rep)?);
        }
        bail!("verification attestation write failed: {e:#}");
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rep)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&rep)?);
        if rep.ok {
            println!("verify: PASS");
        }
    }
    if !rep.ok {
        bail!("evidence verify FAILED: {} errors", rep.errors.len());
    }
    Ok(())
}

fn cmd_report(run_id: &str, format: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = cwd.join(".tomorrowci/runs").join(run_id);
    let m = load_run_manifest(&root)?;
    match format {
        "html" => {
            let p = root.join("report.html");
            write_html_report(&m, &p)?;
            println!("wrote {}", p.display());
        }
        "sarif" => {
            let p = root.join("report.sarif.json");
            write_sarif_stub(&m, &p)?;
            println!("wrote {}", p.display());
        }
        "summary" => {
            let p = root.join("job-summary.md");
            write_github_job_summary(&m, &p)?;
            println!("wrote {}", p.display());
        }
        _ => {
            let p = root.join("report.json");
            write_json_report(&m, &p)?;
            println!("wrote {}", p.display());
        }
    }
    Ok(())
}

fn cmd_compare(base: &str, head: &str, gate: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let base_m = load_run_manifest(&cwd.join(".tomorrowci/runs").join(base))?;
    let head_m = load_run_manifest(&cwd.join(".tomorrowci/runs").join(head))?;
    let cmp = compare_horizons(&base_m.frontier, &head_m.frontier);
    println!("{}", serde_json::to_string_pretty(&cmp)?);

    if gate {
        let baseline_invalid = head_m
            .results
            .iter()
            .any(|r| r.verdict == Verdict::BaselineInvalid);
        let new_future_failure = head_m
            .results
            .iter()
            .any(|r| r.verdict == Verdict::FutureFail)
            && !base_m
                .results
                .iter()
                .any(|r| r.verdict == Verdict::FutureFail);
        let horizon_regression = cmp.delta == HorizonDelta::Regression;
        let blocked = head_m
            .results
            .iter()
            .filter(|r| r.verdict == Verdict::Blocked)
            .count() as f64;
        let total = head_m.results.len().max(1) as f64;
        let g = evaluate_policy_gate(
            baseline_invalid,
            new_future_failure,
            horizon_regression,
            blocked / total,
            Some(0.50),
            true,
            true,
            true,
        );
        println!("policy_gate: {}", serde_json::to_string_pretty(&g)?);
        if g.fail {
            std::process::exit(3);
        }
    }
    Ok(())
}

fn cmd_metrics(run_id: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let p = cwd
        .join(".tomorrowci/runs")
        .join(run_id)
        .join("metrics.json");
    if p.exists() {
        print!("{}", std::fs::read_to_string(p)?);
        return Ok(());
    }
    // recompute from run.json
    let m = load_run_manifest(&cwd.join(".tomorrowci/runs").join(run_id))?;
    let metrics = ScanMetrics::from_manifest(&m, None);
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    Ok(())
}

fn cmd_init_action(out: &Path) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(out, include_str!("../../../action/workflow-template.yml"))?;
    println!("wrote {}", out.display());
    Ok(())
}
