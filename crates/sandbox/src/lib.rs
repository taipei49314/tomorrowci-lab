//! Sandbox: Docker/Podman isolation. Never run target code on host by default.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tomorrowci_core::{CommandSpec, EnvironmentSpec, RawExecutionResult, Result, TcError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxEngine {
    Docker,
    Podman,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAvailability {
    pub docker: bool,
    pub podman: bool,
    pub selected: Option<SandboxEngine>,
    pub engine_version: Option<String>,
    pub notes: Vec<String>,
}

pub fn detect_engines() -> SandboxAvailability {
    let docker = engine_alive("docker");
    let podman = engine_alive("podman");
    let mut notes = Vec::new();
    let selected = if docker {
        notes.push("Docker daemon responsive.".into());
        Some(SandboxEngine::Docker)
    } else if podman {
        notes.push("Podman responsive.".into());
        Some(SandboxEngine::Podman)
    } else {
        notes.push(
            "Neither Docker nor Podman daemon available; sandbox execution is BLOCKED.".into(),
        );
        if which_exists("docker") {
            notes.push("docker CLI found but daemon not responding.".into());
        }
        None
    };
    let engine_version = selected.and_then(engine_version_string);
    SandboxAvailability {
        docker,
        podman,
        selected,
        engine_version,
        notes,
    }
}

fn which_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn engine_alive(bin: &str) -> bool {
    Command::new(bin)
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn engine_version_string(engine: SandboxEngine) -> Option<String> {
    let bin = engine_bin(engine);
    let out = Command::new(bin)
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    let out2 = Command::new(bin).args(["--version"]).output().ok()?;
    Some(String::from_utf8_lossy(&out2.stdout).trim().to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityPolicy {
    pub privileged: bool,
    pub mount_docker_socket: bool,
    pub forward_host_env: bool,
    pub network_during_test: bool,
    pub mutate_user_repo: bool,
}

impl SecurityPolicy {
    pub fn validate_safe_defaults(&self) -> Result<()> {
        if self.privileged {
            return Err(TcError::InvalidState(
                "privileged containers are forbidden".into(),
            ));
        }
        if self.mount_docker_socket {
            return Err(TcError::InvalidState(
                "mounting docker.sock into target is forbidden".into(),
            ));
        }
        if self.mutate_user_repo {
            return Err(TcError::InvalidState(
                "mutating the user repository is forbidden".into(),
            ));
        }
        Ok(())
    }
}

pub fn refuse_host_execution() -> Result<()> {
    Err(TcError::Blocked(
        "target code must not execute on the host by default; use Docker/Podman sandbox".into(),
    ))
}

/// Copy repo into disposable workspace (does not mutate original).
pub fn make_disposable_copy(src: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        let _ = std::fs::remove_dir_all(dest);
    }
    copy_dir_filtered(src, dest)?;
    Ok(())
}

fn copy_dir_filtered(src: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        if matches!(
            name_s.as_ref(),
            "target" | "node_modules" | ".git" | ".tomorrowci" | "__pycache__" | ".venv" | "venv"
        ) {
            continue;
        }
        let from = entry.path();
        let to = dest.join(&name);
        if from.is_symlink() {
            continue;
        }
        if from.is_dir() {
            copy_dir_filtered(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Prepare scenario-local writable state under the disposable workspace.
pub fn prepare_scenario_state(workspace: &Path) -> Result<PathBuf> {
    let root = workspace.join(".tomorrowci");
    let venv = root.join("venv");
    let cache = root.join("cache").join("pip");
    std::fs::create_dir_all(&venv)?;
    std::fs::create_dir_all(&cache)?;
    // Ensure non-root container user can write (best-effort on Windows mounts).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::Permissions::from_mode(0o777);
        let _ = std::fs::set_permissions(&root, mode.clone());
        let _ = std::fs::set_permissions(&venv, mode.clone());
        let _ = std::fs::set_permissions(workspace.join(".tomorrowci/cache"), mode.clone());
        let _ = std::fs::set_permissions(&cache, mode);
    }
    Ok(root)
}

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub engine: SandboxEngine,
    /// Prefer immutable ref `image@sha256:...` when available.
    pub image: String,
    pub workspace_host: PathBuf,
    pub workdir: String,
    pub commands: Vec<CommandSpec>,
    pub env: HashMap<String, String>,
    pub memory_mb: u32,
    pub cpus: f32,
    pub pids_limit: u32,
    pub network: String,
    pub timeout: Duration,
    pub read_only_root: bool,
    pub user: Option<String>,
    /// When true, record only argv execution via `sh -c` with proven escaping.
    pub use_shell: bool,
}

/// Pull image if needed and return an immutable digest ref (`repo@sha256:...` or `sha256:...`).
pub fn resolve_or_pull_digest(engine: SandboxEngine, image: &str) -> Result<String> {
    if let Some(d) = resolve_image_digest(engine, image) {
        return Ok(d);
    }
    pull_image(engine, image)?;
    resolve_image_digest(engine, image).ok_or_else(|| {
        TcError::Blocked(format!(
            "image {image} pulled but immutable digest could not be resolved"
        ))
    })
}

pub fn resolve_image_digest(engine: SandboxEngine, image: &str) -> Option<String> {
    let bin = engine_bin(engine);
    // Already a digest-pinned ref
    if image.contains("@sha256:") {
        return Some(image.to_string());
    }
    let out = Command::new(bin)
        .args([
            "image",
            "inspect",
            "--format",
            "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}",
            image,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s == "<no value>" {
        return None;
    }
    // Normalize Id-only to sha256:...
    if s.starts_with("sha256:") || s.contains("@sha256:") {
        Some(s)
    } else if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(format!("sha256:{s}"))
    } else {
        Some(s)
    }
}

pub fn pull_image(engine: SandboxEngine, image: &str) -> Result<()> {
    let bin = engine_bin(engine);
    let st = Command::new(bin)
        .args(["pull", image])
        .status()
        .map_err(|e| TcError::Blocked(format!("failed to spawn {bin} pull: {e}")))?;
    if !st.success() {
        return Err(TcError::Blocked(format!("failed to pull image {image}")));
    }
    Ok(())
}

fn engine_bin(engine: SandboxEngine) -> &'static str {
    match engine {
        SandboxEngine::Docker => "docker",
        SandboxEngine::Podman => "podman",
    }
}

/// Run commands inside a container. Network should be "none" for test phase.
pub fn run_in_container(req: &RunRequest) -> Result<RawExecutionResult> {
    SecurityPolicy::default().validate_safe_defaults()?;
    let bin = engine_bin(req.engine);
    let workspace =
        std::fs::canonicalize(&req.workspace_host).unwrap_or_else(|_| req.workspace_host.clone());
    let mount = format!("{}:{}:rw", workspace.display(), req.workdir);

    let mut docker_args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--network".into(),
        req.network.clone(),
        "--memory".into(),
        format!("{}m", req.memory_mb),
        "--cpus".into(),
        req.cpus.to_string(),
        "--pids-limit".into(),
        req.pids_limit.to_string(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "-v".into(),
        mount,
        "-w".into(),
        req.workdir.clone(),
    ];
    if req.read_only_root {
        docker_args.push("--read-only".into());
        docker_args.push("--tmpfs".into());
        docker_args.push("/tmp:rw,exec,nosuid,size=256m".into());
        // venv creation needs write under /work which is mounted rw
    }
    if let Some(user) = &req.user {
        docker_args.push("--user".into());
        docker_args.push(user.clone());
    }
    for (k, v) in &req.env {
        if is_forbidden_env(k) {
            continue;
        }
        docker_args.push("-e".into());
        docker_args.push(format!("{k}={v}"));
    }
    docker_args.push(req.image.clone());

    if req.use_shell
        || req.commands.len() > 1
        || req
            .commands
            .iter()
            .any(|c| c.argv.len() > 1 && needs_shell(&c.argv))
    {
        let shell_cmd = req
            .commands
            .iter()
            .map(|c| shell_join(&c.argv))
            .collect::<Vec<_>>()
            .join(" && ");
        docker_args.push("sh".into());
        docker_args.push("-c".into());
        docker_args.push(shell_cmd);
    } else if let Some(cmd) = req.commands.first() {
        // Direct argv — recorded argv matches executed argv
        for a in &cmd.argv {
            docker_args.push(a.clone());
        }
    } else {
        return Err(TcError::InvalidState("no commands to execute".into()));
    }

    let start = Instant::now();
    let mut child = Command::new(bin)
        .args(&docker_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| TcError::Blocked(format!("container spawn failed: {e}")))?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let (tx_out, rx_out) = mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = mpsc::channel::<Vec<u8>>();
    if let Some(mut out) = stdout_pipe {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            let _ = tx_out.send(buf);
        });
    }
    if let Some(mut err) = stderr_pipe {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf);
            let _ = tx_err.send(buf);
        });
    }

    let timed_out = wait_with_timeout(&mut child, req.timeout)?;
    let status = child
        .wait()
        .map_err(|e| TcError::Blocked(format!("wait failed: {e}")))?;

    let stdout_bytes = rx_out
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    let stderr_bytes = rx_err
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();

    let duration_ms = start.elapsed().as_millis() as u64;
    let stdout = redact_secrets(&truncate_log(
        &String::from_utf8_lossy(&stdout_bytes),
        512 * 1024,
    ));
    let stderr = redact_secrets(&truncate_log(
        &String::from_utf8_lossy(&stderr_bytes),
        512 * 1024,
    ));

    Ok(RawExecutionResult {
        exit_code: if timed_out { None } else { status.code() },
        signal: None,
        duration_ms,
        timed_out,
        stdout,
        stderr,
        network_used: req.network != "none",
    })
}

fn needs_shell(argv: &[String]) -> bool {
    // Prefer shell only when metacharacters require a shell pipeline
    argv.iter()
        .any(|a| a.contains('|') || a.contains('>') || a.contains('<') || a.contains('&'))
}

fn wait_with_timeout(child: &mut std::process::Child, timeout: Duration) -> Result<bool> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(false),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(true);
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(TcError::Blocked(format!("try_wait: {e}"))),
        }
    }
}

/// POSIX-style single-quote shell joining so recorded argv and shell form stay aligned.
pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn shell_quote(a: &str) -> String {
    // Always single-quote; escape embedded single quotes with '\''
    format!("'{}'", a.replace('\'', "'\\''"))
}

fn is_forbidden_env(k: &str) -> bool {
    let u = k.to_ascii_uppercase();
    u.contains("SECRET")
        || u.contains("TOKEN")
        || u.contains("PASSWORD")
        || u.starts_with("AWS_")
        || u == "SSH_AUTH_SOCK"
}

pub fn redact_secrets(s: &str) -> String {
    // Simple pattern redaction for persisted logs
    let mut out = s.to_string();
    for pat in [
        "password=",
        "PASSWORD=",
        "token=",
        "TOKEN=",
        "secret=",
        "SECRET=",
    ] {
        if let Some(idx) = out.find(pat) {
            let rest = &out[idx + pat.len()..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(rest.len());
            out = format!(
                "{}{}***REDACTED***{}",
                &out[..idx + pat.len()],
                "",
                &rest[end..]
            );
        }
    }
    out
}

/// Truncate without slicing inside a UTF-8 code point.
pub fn truncate_log(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n...[truncated {} bytes]...\n",
        &s[..end],
        s.len().saturating_sub(end)
    )
}

pub fn env_spec_to_map(spec: &EnvironmentSpec) -> HashMap<String, String> {
    spec.env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Cap number of artifact files recorded under a scenario directory.
pub const MAX_SCENARIO_ARTIFACTS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_defaults() {
        SecurityPolicy::default().validate_safe_defaults().unwrap();
    }

    #[test]
    fn host_execution_refused() {
        assert!(refuse_host_execution().is_err());
    }

    #[test]
    fn disposable_copy_skips_git() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(src.join(".git")).unwrap();
        std::fs::write(src.join("a.py"), "x").unwrap();
        std::fs::write(src.join(".git/x"), "no").unwrap();
        let dest = d.path().join("dest");
        make_disposable_copy(&src, &dest).unwrap();
        assert!(dest.join("a.py").exists());
        assert!(!dest.join(".git").exists());
    }

    #[test]
    fn utf8_truncate_never_panics() {
        let s = "hello 😀 world 世界";
        let t = truncate_log(s, 8);
        assert!(t.contains("truncated") || t.len() <= s.len());
        // mid-emoji boundary
        let emoji = "aa😀bb";
        let _ = truncate_log(emoji, 3);
        let _ = truncate_log(emoji, 4);
        let _ = truncate_log(emoji, 5);
    }

    #[test]
    fn shell_quote_metacharacters() {
        let q = shell_quote("a b;$(echo hi)");
        assert!(q.starts_with('\''));
        assert!(
            shell_join(&["echo".into(), "hello world".into(), "x;y".into()])
                .contains("'hello world'")
        );
    }

    #[test]
    fn redact_password() {
        let s = redact_secrets("export password=supersecret rest");
        assert!(s.contains("***REDACTED***"));
        assert!(!s.contains("supersecret"));
    }
}
