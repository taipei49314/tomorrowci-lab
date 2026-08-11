//! Rust adapter (cargo only). Supports stable/beta/nightly and pinned versions.

use indexmap::IndexMap;
use std::path::Path;
use tomorrowci_adapters::{path_exists, DetectionResult, EcosystemAdapter};
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec,
    EvidenceGrade, FailureSignature, ProjectDetection, RawExecutionResult, Result, Scenario,
};

pub struct RustAdapter;

impl EcosystemAdapter for RustAdapter {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, repo: &Path) -> DetectionResult {
        let has = path_exists(repo, "Cargo.toml");
        // Prefer fixture/app crates; monorepos with workspace still supported.
        DetectionResult {
            supported: has,
            detection: ProjectDetection {
                ecosystem: if has {
                    Ecosystem::Rust
                } else {
                    Ecosystem::Unknown
                },
                manifests: if has {
                    let mut m = vec!["Cargo.toml".into()];
                    if path_exists(repo, "Cargo.lock") {
                        m.push("Cargo.lock".into());
                    }
                    m
                } else {
                    vec![]
                },
                package_manager: "cargo".into(),
                confidence: if has { 0.95 } else { 0.0 },
                notes: vec![],
            },
        }
    }

    fn baseline(&self, _repo: &Path, config: &Config) -> Result<Baseline> {
        let runtime = if config.baseline.runtime == "auto" {
            "1.83".into() // concrete recent stable pin for reproducibility
        } else {
            config
                .baseline
                .runtime
                .trim_start_matches("rust:")
                .to_string()
        };
        Ok(Baseline {
            runtime,
            dependencies: if config.baseline.dependencies == "auto" {
                "locked".into()
            } else {
                config.baseline.dependencies.clone()
            },
            declared_by: "config/auto".into(),
        })
    }

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>> {
        let max = config.candidates.runtime.max_versions as usize;
        if max == 0 {
            return Ok(vec![]);
        }
        let stable_enabled = config
            .candidates
            .runtime
            .channels
            .iter()
            .any(|channel| channel == "stable");
        let preview_enabled = config
            .candidates
            .runtime
            .channels
            .iter()
            .any(|channel| channel == "preview" || channel == "nightly");

        // `rust:beta-bookworm` is not a published OCI reference. Keep the
        // declared-MSRV stable probe and the independently published nightly
        // preview image explicit instead of manufacturing an invalid tag.
        let versions = [("1.74", "stable"), ("nightly", "preview")];
        let mut out = Vec::new();
        for (i, (v, channel)) in versions.iter().enumerate() {
            if out.len() >= max {
                break;
            }
            if (*channel == "stable" && !stable_enabled)
                || (*channel == "preview" && !preview_enabled)
            {
                continue;
            }
            if *v == baseline.runtime.as_str() {
                continue;
            }
            out.push(Candidate {
                id: format!("rust-{}", v.replace('.', "")),
                axis: EnvironmentAxis::Runtime,
                label: format!("Rust {v} toolchain"),
                version: (*v).into(),
                channel: (*channel).into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{i:04}"),
                dependency_set: None,
            });
        }
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        let tag = scenario.runtime.trim_start_matches("rust:");
        let image = if tag == "nightly" {
            "rustlang/rust:nightly".into()
        } else {
            format!("rust:{tag}-bookworm")
        };
        Ok(EnvironmentSpec {
            image_tag: image.clone(),
            image: image.clone(),
            image_digest: None,
            workdir: "/work".into(),
            env: {
                let state = format!("/work/.tomorrowci/scenarios/{}", scenario.id);
                let mut env = IndexMap::new();
                env.insert("CARGO_HOME".into(), format!("{state}/cargo"));
                env.insert("CARGO_TARGET_DIR".into(), format!("{state}/target"));
                env
            },
            network_mode: "none".into(),
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            user: None,
            read_only_root: false,
            scenario_state_root: None,
            fetch_timeout_seconds: None,
            test_timeout_seconds: None,
            engine: None,
            engine_version: None,
        })
    }

    fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let argv = if config.project.test_command == "auto" {
            vec![
                "cargo".into(),
                "test".into(),
                "--".into(),
                "--nocapture".into(),
            ]
        } else {
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        let argv = if config.project.test_command == "auto" {
            let mut argv = vec!["cargo".into(), "test".into()];
            if scenario.resolved_dependencies.is_some() {
                argv.extend(["--offline".into(), "--locked".into()]);
            }
            argv
        } else {
            argv
        };
        let mut commands = vec![
            CommandSpec {
                argv: vec!["rustc".into(), "--version".into(), "--verbose".into()],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
            CommandSpec {
                argv: vec!["cargo".into(), "--version".into(), "--verbose".into()],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
            CommandSpec {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "if [ -f Cargo.lock ]; then sha256sum Cargo.lock; else printf '%s\\n' 'Cargo.lock:ABSENT'; fi".into(),
                ],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
        ];
        commands.push(CommandSpec {
            argv,
            cwd: Some("/work".into()),
            network: false,
            phase: "test".into(),
        });
        Ok(commands)
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        let blob = format!("{}\n{}", result.stdout, result.stderr);
        let kind = if blob.contains("package.rust-version")
            || blob.contains("rust-version")
            || (blob.contains("requires rustc")
                && (blob.contains("cannot be built") || blob.contains("is not supported")))
        {
            "MsrvError"
        } else if blob.contains("error[E") {
            "CompileError"
        } else {
            "TestFailure"
        };
        FailureSignature {
            kind: kind.into(),
            summary: blob
                .lines()
                .find(|l| l.contains("error"))
                .unwrap_or(kind)
                .chars()
                .take(200)
                .collect(),
            normalized_hash: tomorrowci_core::sha256_str(kind),
            primary_frame: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_cargo() {
        let d = tempdir().unwrap();
        std::fs::write(
            d.path().join("Cargo.toml"),
            "[package]\nname=\"x\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        assert!(RustAdapter.detect(d.path()).supported);
    }

    #[test]
    fn candidates_respect_max_zero() {
        let mut cfg = Config::default();
        cfg.candidates.runtime.max_versions = 0;
        let b = Baseline {
            runtime: "1.83".into(),
            dependencies: "locked".into(),
            declared_by: "t".into(),
        };
        assert!(RustAdapter.candidates(&b, &cfg).unwrap().is_empty());
    }

    #[test]
    fn stable_channel_does_not_manufacture_preview_tags() {
        let mut cfg = Config::default();
        cfg.candidates.runtime.channels = vec!["stable".into()];
        cfg.candidates.runtime.max_versions = 3;
        let baseline = Baseline {
            runtime: "1.83".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };

        let candidates = RustAdapter.candidates(&baseline, &cfg).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].version, "1.74");
        assert_eq!(candidates[0].channel, "stable");
    }

    #[test]
    fn preview_channel_uses_the_published_nightly_image() {
        let mut cfg = Config::default();
        cfg.candidates.runtime.channels = vec!["preview".into()];
        cfg.candidates.runtime.max_versions = 1;
        let baseline = Baseline {
            runtime: "1.83".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };

        let candidate = RustAdapter.candidates(&baseline, &cfg).unwrap().remove(0);
        assert_eq!(candidate.version, "nightly");
        let scenario = Scenario {
            id: candidate.id,
            is_baseline: false,
            runtime: candidate.version,
            dependencies: "locked".into(),
            axes_changed: vec![EnvironmentAxis::Runtime],
            candidates: vec![],
            grade: EvidenceGrade::Observed,
            resolved_dependencies: None,
        };
        assert_eq!(
            RustAdapter
                .materialize(&scenario, Path::new("."))
                .unwrap()
                .image,
            "rustlang/rust:nightly"
        );
    }

    #[test]
    fn declared_msrv_failure_has_stable_signature() {
        let raw = RawExecutionResult {
            exit_code: Some(101),
            signal: None,
            duration_ms: 1,
            timed_out: false,
            stdout: String::new(),
            stderr: "error: package `rust-msrv-break v0.1.0 (/work)` cannot be built because it requires rustc 1.80 or newer, while the currently active rustc version is 1.74.1".into(),
            network_used: false,
        };

        let signature = RustAdapter.normalize_failure(&raw);
        assert_eq!(signature.kind, "MsrvError");
        assert_eq!(
            signature.normalized_hash,
            tomorrowci_core::sha256_str("MsrvError")
        );
    }
}
