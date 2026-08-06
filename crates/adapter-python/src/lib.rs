//! Python adapter — pip-only live runtime forecasting path.

use indexmap::IndexMap;
use std::path::Path;
use tomorrowci_adapters::{path_exists, DetectionResult, EcosystemAdapter};
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec,
    EvidenceGrade, FailureSignature, ProjectDetection, RawExecutionResult, Result, Scenario,
    TcError,
};

pub struct PythonAdapter;

/// Parse `3.9`, `python:3.10`, `3.11-slim` → (major, minor).
pub fn parse_python_version(s: &str) -> Option<(u32, u32)> {
    let t = s
        .trim()
        .trim_start_matches("python:")
        .split('-')
        .next()
        .unwrap_or("")
        .trim();
    let mut parts = t.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn version_order_key(major: u32, minor: u32) -> String {
    format!("{major:03}.{minor:03}")
}

impl EcosystemAdapter for PythonAdapter {
    fn name(&self) -> &'static str {
        "python"
    }

    fn detect(&self, repo: &Path) -> DetectionResult {
        let has_pyproject = path_exists(repo, "pyproject.toml");
        let has_req = path_exists(repo, "requirements.txt");
        let supported = has_pyproject || has_req;
        let mut manifests = Vec::new();
        if has_pyproject {
            manifests.push("pyproject.toml".into());
        }
        if has_req {
            manifests.push("requirements.txt".into());
        }
        let notes = if supported {
            let mut n = vec!["Python project detected; package manager: pip only.".into()];
            if has_pyproject && !has_req {
                n.push(
                    "pyproject.toml without requirements.txt: install path is UNSUPPORTED for this milestone unless requirements.txt is present."
                        .into(),
                );
            }
            n
        } else {
            vec!["No pyproject.toml or requirements.txt.".into()]
        };
        DetectionResult {
            supported,
            detection: ProjectDetection {
                ecosystem: if supported {
                    Ecosystem::Python
                } else {
                    Ecosystem::Unknown
                },
                manifests,
                package_manager: "pip".into(),
                confidence: if supported { 0.9 } else { 0.0 },
                notes,
            },
        }
    }

    fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline> {
        // Prefer explicit config; never silently invent unrelated projects' baselines.
        let runtime = if config.baseline.runtime == "auto" {
            // Read requires-python from pyproject if present; else fail closed to config requirement.
            if let Some(v) = read_requires_python_min(repo) {
                v
            } else {
                return Err(TcError::Config(
                    "baseline.runtime is 'auto' but no requires-python / config pin found; set baseline.runtime explicitly (e.g. \"3.9\")".into(),
                ));
            }
        } else {
            config
                .baseline
                .runtime
                .trim_start_matches("python:")
                .split('-')
                .next()
                .unwrap_or(&config.baseline.runtime)
                .to_string()
        };
        if parse_python_version(&runtime).is_none() {
            return Err(TcError::Config(format!(
                "invalid Python baseline runtime '{runtime}'"
            )));
        }
        Ok(Baseline {
            runtime,
            dependencies: if config.baseline.dependencies == "auto" {
                "locked".into()
            } else {
                config.baseline.dependencies.clone()
            },
            declared_by: if config.baseline.runtime == "auto" {
                "pyproject/requires-python".into()
            } else {
                "config".into()
            },
        })
    }

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>> {
        let max = config.candidates.runtime.max_versions as usize;
        let base = parse_python_version(&baseline.runtime).ok_or_else(|| {
            TcError::Config(format!(
                "cannot order candidates: invalid baseline {}",
                baseline.runtime
            ))
        })?;

        // Concrete published CPython tags — never invent versions.
        let catalog = [(3, 10), (3, 11), (3, 12), (3, 13)];
        let mut out = Vec::new();
        for (maj, min) in catalog {
            if (maj, min) <= base {
                continue; // strictly later only
            }
            if out.len() >= max {
                break;
            }
            let v = format!("{maj}.{min}");
            out.push(Candidate {
                id: format!("py{}{}-locked", maj, min),
                axis: EnvironmentAxis::Runtime,
                label: format!("Python {v} + locked dependencies"),
                version: v,
                channel: "stable".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: version_order_key(maj, min),
            });
        }
        out.sort_by(|a, b| a.order_key.cmp(&b.order_key));
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        let ver = scenario
            .runtime
            .trim_start_matches("python:")
            .split('-')
            .next()
            .unwrap_or(&scenario.runtime);
        Ok(EnvironmentSpec {
            image: format!("python:{ver}-slim"),
            image_digest: None,
            workdir: "/work".into(),
            env: {
                let mut m = IndexMap::new();
                m.insert("PIP_CACHE_DIR".into(), "/work/.tomorrowci/cache/pip".into());
                m.insert("VIRTUAL_ENV".into(), "/work/.tomorrowci/venv".into());
                m.insert(
                    "PATH".into(),
                    "/work/.tomorrowci/venv/bin:/usr/local/bin:/usr/bin:/bin".into(),
                );
                m
            },
            network_mode: "none".into(),
            memory_mb: 2048,
            cpus: 1.0,
            pids_limit: 256,
            // Non-root; workspace mount is rw for scenario-local venv
            user: Some("65534:65534".into()),
            read_only_root: true,
        })
    }

    fn commands(&self, _scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        // Test must use scenario-local venv Python
        let test = if config.project.test_command == "auto" {
            vec![
                "/work/.tomorrowci/venv/bin/python".into(),
                "-m".into(),
                "pytest".into(),
                "-q".into(),
            ]
        } else {
            // Prefer rewriting bare `python` to venv python for fixture default
            let parts: Vec<String> = config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            if parts.first().map(|s| s.as_str()) == Some("python") {
                let mut p = parts;
                p[0] = "/work/.tomorrowci/venv/bin/python".into();
                p
            } else {
                parts
            }
        };
        Ok(vec![CommandSpec {
            argv: test,
            cwd: Some("/work".into()),
            network: false,
            phase: "test".into(),
        }])
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        let blob = format!("{}\n{}", result.stdout, result.stderr);
        let kind = if blob.contains("ImportError") || blob.contains("cannot import name") {
            "ImportError"
        } else if blob.contains("SyntaxError") {
            "SyntaxError"
        } else if result.timed_out {
            "Timeout"
        } else if blob.contains("ModuleNotFoundError") {
            "ModuleNotFoundError"
        } else {
            "TestFailure"
        };
        // Normalize: prefer stable ImportError line about MutableMapping when present
        let summary = blob
            .lines()
            .find(|l| {
                l.contains("MutableMapping") || l.contains("ImportError") || l.contains("Error")
            })
            .or_else(|| blob.lines().rev().find(|l| !l.trim().is_empty()))
            .unwrap_or(kind)
            .chars()
            .take(200)
            .collect::<String>();
        let normalized_hash = tomorrowci_core::sha256_str(&format!("{kind}:{summary}"));
        FailureSignature {
            kind: kind.into(),
            summary,
            normalized_hash,
            primary_frame: None,
        }
    }
}

/// Fetch phase: create venv in mounted workspace and pip install requirements.
pub fn python_fetch_commands(workspace: &Path, upgrade: bool) -> Result<Vec<CommandSpec>> {
    if !workspace.join("requirements.txt").exists() {
        // pyproject-only without requirements: UNSUPPORTED for this milestone
        return Err(TcError::Unsupported(
            "Python install path requires requirements.txt in this repair milestone (pip only); pyproject-only is UNSUPPORTED".into(),
        ));
    }
    let mut install = vec![
        "/work/.tomorrowci/venv/bin/pip".into(),
        "install".into(),
        "-q".into(),
        "--cache-dir".into(),
        "/work/.tomorrowci/cache/pip".into(),
        "-r".into(),
        "requirements.txt".into(),
    ];
    if upgrade {
        install.push("--upgrade".into());
    }
    Ok(vec![
        CommandSpec {
            argv: vec![
                "python".into(),
                "-m".into(),
                "venv".into(),
                "/work/.tomorrowci/venv".into(),
            ],
            cwd: Some("/work".into()),
            network: false,
            phase: "fetch".into(),
        },
        CommandSpec {
            argv: install,
            cwd: Some("/work".into()),
            network: true,
            phase: "fetch".into(),
        },
    ])
}

fn read_requires_python_min(repo: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(repo.join("pyproject.toml")).ok()?;
    // minimal parse: requires-python = ">=3.9"
    for line in raw.lines() {
        let t = line.trim();
        if t.starts_with("requires-python") {
            if let Some(idx) = t.find('"') {
                let rest = &t[idx + 1..];
                if let Some(end) = rest.find('"') {
                    let spec = &rest[..end];
                    // take first X.Y mentioned
                    for token in spec.split(|c: char| !c.is_ascii_digit() && c != '.') {
                        if parse_python_version(token).is_some() {
                            return Some(token.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Explicit: only pip is supported in this repair milestone.
pub fn check_manager_supported(manager: &str) -> Result<()> {
    match manager {
        "pip" => Ok(()),
        "uv" => Err(TcError::Unsupported(
            "Python package manager 'uv' is NOT_RUN / UNSUPPORTED in this repair milestone (pip only)".into(),
        )),
        other => Err(TcError::Unsupported(format!(
            "Python package manager '{other}' is UNSUPPORTED (supported: pip)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_requirements() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("requirements.txt"), "pytest\n").unwrap();
        let det = PythonAdapter.detect(d.path());
        assert!(det.supported);
        assert_eq!(det.detection.ecosystem, Ecosystem::Python);
    }

    #[test]
    fn poetry_unsupported() {
        assert!(check_manager_supported("poetry").is_err());
    }

    #[test]
    fn uv_not_supported_claim() {
        assert!(check_manager_supported("uv").is_err());
    }

    #[test]
    fn candidates_strictly_later_semantic() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("requirements.txt"), "pytest\n").unwrap();
        let mut cfg = Config::default();
        cfg.baseline.runtime = "3.11".into();
        cfg.candidates.runtime.max_versions = 5;
        let base = PythonAdapter.baseline(d.path(), &cfg).unwrap();
        let c = PythonAdapter.candidates(&base, &cfg).unwrap();
        assert!(c
            .iter()
            .all(|x| parse_python_version(&x.version).unwrap() > (3, 11)));
        assert_eq!(c.first().map(|x| x.version.as_str()), Some("3.12"));
        // order keys semantic not lexical-only
        let keys: Vec<_> = c.iter().map(|x| x.order_key.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn no_hardcoded_silent_39_for_auto_without_pyproject() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("requirements.txt"), "pytest\n").unwrap();
        let mut cfg = Config::default();
        cfg.baseline.runtime = "auto".into();
        assert!(PythonAdapter.baseline(d.path(), &cfg).is_err());
    }
}
