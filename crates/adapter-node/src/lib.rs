//! Node adapter (npm only in v0.1). yarn/pnpm => UNSUPPORTED.

use indexmap::IndexMap;
use std::path::Path;
use tomorrowci_adapters::{path_exists, DetectionResult, EcosystemAdapter};
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec,
    EvidenceGrade, FailureSignature, ProjectDetection, RawExecutionResult, Result, Scenario,
    TcError,
};

pub struct NodeAdapter;

impl EcosystemAdapter for NodeAdapter {
    fn name(&self) -> &'static str {
        "node"
    }

    fn detect(&self, repo: &Path) -> DetectionResult {
        let has_pkg = path_exists(repo, "package.json");
        let has_lock = path_exists(repo, "package-lock.json");
        let yarn = path_exists(repo, "yarn.lock");
        let pnpm = path_exists(repo, "pnpm-lock.yaml");
        let mut notes = Vec::new();
        if yarn && !has_lock {
            notes.push("yarn.lock without package-lock.json => yarn UNSUPPORTED in v0.1.".into());
        }
        if pnpm && !has_lock {
            notes.push(
                "pnpm-lock.yaml without package-lock.json => pnpm UNSUPPORTED in v0.1.".into(),
            );
        }
        // Supported when package.json exists and we are not forced onto yarn/pnpm-only.
        let supported = has_pkg && !(yarn && !has_lock) && !(pnpm && !has_lock);
        DetectionResult {
            supported,
            detection: ProjectDetection {
                ecosystem: if has_pkg {
                    Ecosystem::Node
                } else {
                    Ecosystem::Unknown
                },
                manifests: {
                    let mut m = Vec::new();
                    if has_pkg {
                        m.push("package.json".into());
                    }
                    if has_lock {
                        m.push("package-lock.json".into());
                    }
                    m
                },
                package_manager: "npm".into(),
                confidence: if supported { 0.9 } else { 0.0 },
                notes,
            },
        }
    }

    fn baseline(&self, _repo: &Path, config: &Config) -> Result<Baseline> {
        let runtime = if config.baseline.runtime == "auto" {
            "20".into()
        } else {
            config
                .baseline
                .runtime
                .trim_start_matches("node:")
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
        let baseline_major = baseline
            .runtime
            .split('.')
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| {
                TcError::Config(format!(
                    "Node baseline runtime must begin with a numeric major version: {:?}",
                    baseline.runtime
                ))
            })?;

        // Concrete, monotonically newer Node.js major tags. A runtime horizon
        // must never be authorized by silently testing an older runtime first.
        let versions = [18_u32, 20, 22, 24];
        let mut out = Vec::new();
        for v in versions {
            if out.len() >= max {
                break;
            }
            if v <= baseline_major {
                continue;
            }
            out.push(Candidate {
                id: format!("node{v}-locked"),
                axis: EnvironmentAxis::Runtime,
                label: format!("Node {v} + locked dependencies"),
                version: v.to_string(),
                channel: "stable".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{v:04}"),
                dependency_set: None,
            });
        }
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        let tag = scenario.runtime.trim_start_matches("node:");
        let image = format!("node:{tag}");
        Ok(EnvironmentSpec {
            image_tag: image.clone(),
            image,
            image_digest: None,
            workdir: "/work".into(),
            env: {
                let mut env = IndexMap::new();
                env.insert(
                    "NODE_PATH".into(),
                    format!(
                        "/work/.tomorrowci/scenarios/{}/node-project/node_modules",
                        scenario.id
                    ),
                );
                env
            },
            network_mode: "none".into(),
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            user: Some("node".into()),
            read_only_root: false, // npm needs write for node_modules
            scenario_state_root: None,
            fetch_timeout_seconds: None,
            test_timeout_seconds: None,
            engine: None,
            engine_version: None,
        })
    }

    fn commands(&self, _scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let argv = if config.project.test_command == "auto" {
            vec![
                "npm".into(),
                "test".into(),
                "--".into(),
                "--reporter".into(),
                "tap".into(),
            ]
        } else {
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        // Prefer plain `npm test` for broadest fixture compatibility
        let argv = if config.project.test_command == "auto" {
            vec!["npm".into(), "test".into()]
        } else {
            argv
        };
        let mut commands = vec![
            CommandSpec {
                argv: vec!["node".into(), "--version".into()],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
            CommandSpec {
                argv: vec!["npm".into(), "--version".into()],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
            CommandSpec {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "if [ -f package-lock.json ]; then sha256sum package-lock.json; else printf '%s\\n' 'package-lock.json:ABSENT'; fi".into(),
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
        let kind = if blob.contains("createCipher is not a function") {
            "RemovedRuntimeApi"
        } else if blob.contains("ERR_OSSL_EVP_UNSUPPORTED") {
            "OpenSslUnsupported"
        } else if blob.contains("ERR_REQUIRE_ESM") {
            "ErrRequireEsm"
        } else if blob.contains("Cannot find module") {
            "ModuleNotFound"
        } else if blob.contains("ERR!") {
            "NpmError"
        } else {
            "TestFailure"
        };
        FailureSignature {
            kind: kind.into(),
            summary: blob
                .lines()
                .find(|line| line.contains("createCipher is not a function"))
                .or_else(|| {
                    blob.lines()
                        .find(|line| line.contains("TypeError") || line.contains("Error:"))
                })
                .or_else(|| blob.lines().rev().find(|line| !line.trim().is_empty()))
                .unwrap_or(kind)
                .chars()
                .take(200)
                .collect(),
            normalized_hash: tomorrowci_core::sha256_str(kind),
            primary_frame: None,
        }
    }
}

pub fn check_manager(manager: &str) -> Result<()> {
    if manager == "npm" {
        Ok(())
    } else {
        Err(TcError::Unsupported(format!(
            "Node package manager '{manager}' is UNSUPPORTED (v0.1 supports npm only)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_package_json() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
        assert!(NodeAdapter.detect(d.path()).supported);
    }

    #[test]
    fn yarn_only_unsupported() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        assert!(!NodeAdapter.detect(d.path()).supported);
    }

    #[test]
    fn yarn_unsupported_manager() {
        assert!(check_manager("yarn").is_err());
    }

    #[test]
    fn runtime_candidates_are_strictly_newer_than_baseline() {
        let mut config = Config::default();
        config.candidates.runtime.max_versions = 3;
        let baseline = Baseline {
            runtime: "20.20.2".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };

        let candidates = NodeAdapter.candidates(&baseline, &config).unwrap();
        let versions: Vec<_> = candidates
            .iter()
            .map(|candidate| candidate.version.as_str())
            .collect();
        assert_eq!(versions, vec!["22", "24"]);
        assert!(candidates
            .iter()
            .all(|candidate| candidate.id != "node18-locked"));
    }

    #[test]
    fn non_numeric_runtime_baseline_is_rejected() {
        let mut config = Config::default();
        config.candidates.runtime.max_versions = 1;
        let baseline = Baseline {
            runtime: "current".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };

        let error = NodeAdapter
            .candidates(&baseline, &config)
            .unwrap_err()
            .to_string();
        assert!(error.contains("numeric major version"), "{error}");
    }

    #[test]
    fn removed_runtime_api_has_a_semantic_stable_signature() {
        let raw = RawExecutionResult {
            exit_code: Some(1),
            signal: None,
            duration_ms: 1,
            timed_out: false,
            stdout: String::new(),
            stderr: "TypeError: crypto.createCipher is not a function".into(),
            network_used: false,
        };

        let signature = NodeAdapter.normalize_failure(&raw);
        assert_eq!(signature.kind, "RemovedRuntimeApi");
        assert!(signature.summary.contains("createCipher is not a function"));
        assert_eq!(
            signature.normalized_hash,
            tomorrowci_core::sha256_str("RemovedRuntimeApi")
        );
    }
}
