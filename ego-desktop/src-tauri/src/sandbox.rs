//! Per-reservation compute isolation via Docker.
//!
//! Each active rental gets its own Docker container, resource-capped to exactly
//! what the buyer paid for (`--cpus`, `--memory`, `--gpus`). Renter commands run
//! *inside* that container, so:
//!   * the renter cannot touch the provider host (isolation), and
//!   * usage metering (`docker stats`) reflects the renter's own workload,
//!     not the whole machine.
//!
//! On Linux this is backed by kernel cgroups directly; on Windows/macOS Docker
//! Desktop provides the same limits through its Linux VM. When Docker is not
//! installed the caller falls back to host-shell execution (honestly labelled).

use crate::chain_db::ComputeReservation;
use std::process::Output;
use std::sync::atomic::{AtomicU8, Ordering};

/// Linux base image every sandbox runs. Override with `EGO_SANDBOX_IMAGE`.
/// Defaults to a slim Python so the built-in "AI workspace" actions work.
const DEFAULT_IMAGE: &str = "python:3.12-slim";

/// 0 = unknown, 1 = available, 2 = unavailable. Cached after first probe so we
/// don't shell out to `docker` on every metrics poll.
static DOCKER_STATE: AtomicU8 = AtomicU8::new(0);

fn image() -> String {
    std::env::var("EGO_SANDBOX_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string())
}

/// Docker object names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*. Reservation ids are
/// UUIDs, but sanitise defensively in case of attestation-supplied ids.
fn safe(id: &str) -> String {
    id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect()
}

fn container_name(reservation_id: &str) -> String { format!("ego-rent-{}", safe(reservation_id)) }
fn volume_name(reservation_id: &str)    -> String { format!("ego-rent-{}-ws", safe(reservation_id)) }

/// Whether a Docker daemon is reachable. Result is cached process-wide.
pub fn docker_available() -> bool {
    match DOCKER_STATE.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let ok = std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    DOCKER_STATE.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    ok
}

/// Whether this machine has an NVIDIA GPU reachable via nvidia-smi.
fn nvidia_smi_works() -> bool {
    std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader"])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// Whether the local Docker daemon exposes an NVIDIA GPU runtime, i.e. whether
/// `docker run --gpus ...` can actually inject a GPU into a container.
fn docker_gpu_runtime() -> bool {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{json .Runtimes}}"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase().contains("nvidia"))
        .unwrap_or(false)
}

/// Returns Ok(()) only if this machine can genuinely serve a GPU rental, so a
/// provider is never allowed to list GPU capacity it can't actually deliver.
///
///   * Sandbox mode (Docker present): needs an NVIDIA GPU *and* Docker's NVIDIA
///     runtime, so `--gpus` works inside the Linux container. macOS can never
///     pass a GPU into a container, so it fails here.
///   * Fallback mode (no Docker): the GPU is the host's own, used directly, so
///     a working nvidia-smi is sufficient.
pub fn gpu_deliverable() -> Result<(), String> {
    let host_gpu = nvidia_smi_works();
    if docker_available() {
        if !host_gpu {
            return Err("no NVIDIA GPU detected (nvidia-smi unavailable). Docker can only pass through NVIDIA GPUs.".into());
        }
        if !docker_gpu_runtime() {
            return Err("Docker has no GPU runtime. Install the NVIDIA Container Toolkit (Linux) or enable WSL2 GPU support (Windows). macOS cannot pass a GPU into containers.".into());
        }
        Ok(())
    } else if host_gpu {
        Ok(())
    } else {
        Err("no NVIDIA GPU detected (nvidia-smi unavailable).".into())
    }
}

fn container_running(name: &str) -> bool {
    std::process::Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", name])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

/// Pull the base image ahead of first use so the initial `EXEC` doesn't block on
/// a multi-second image download. Safe to call repeatedly (no-op if cached).
pub fn prewarm_image() {
    if !docker_available() { return; }
    let _ = std::process::Command::new("docker").args(["pull", &image()]).output();
}

/// Create the reservation's container if it isn't already running, capped to the
/// rented CPU/RAM/GPU. Idempotent. Returns the container name on success.
pub fn ensure_container(res: &ComputeReservation) -> Result<String, String> {
    let name = container_name(&res.reservation_id);
    if container_running(&name) {
        return Ok(name);
    }

    // Clear any stopped leftover with the same name before recreating.
    let _ = std::process::Command::new("docker").args(["rm", "-f", &name]).output();

    let cpus = format!("{}", res.cpu_cores.max(1));
    let mem  = format!("{}g", res.ram_gb.max(1));
    let vol  = format!("{}:/workspace", volume_name(&res.reservation_id));

    let mut args: Vec<String> = vec![
        "run".into(), "-d".into(),
        "--name".into(), name.clone(),
        "--cpus".into(), cpus,
        "--memory".into(), mem,
        "--memory-swap".into(), format!("{}g", res.ram_gb.max(1)), // no extra swap beyond rented RAM
        "--pids-limit".into(), "2048".into(),                       // fork-bomb guard
        "--security-opt".into(), "no-new-privileges".into(),
        "-w".into(), "/workspace".into(),
        "-v".into(), vol,
        // Publish common web-app ports to a random localhost host port so the
        // (forthcoming) browser tunnel can reach Jupyter/Gradio/generic apps.
        // 127.0.0.1-only: never exposed off the provider machine directly.
        "-p".into(), "127.0.0.1::8888".into(),
        "-p".into(), "127.0.0.1::7860".into(),
        "-p".into(), "127.0.0.1::8000".into(),
    ];
    if res.gpu_count > 0 {
        args.push("--gpus".into());
        args.push(format!("{}", res.gpu_count));
    }
    args.push(image());
    // Keep the container alive so commands can be exec'd into it across calls.
    args.push("sleep".into());
    args.push("infinity".into());

    let out = std::process::Command::new("docker")
        .args(&args)
        .output()
        .map_err(|e| format!("docker run failed to spawn: {e}"))?;

    if !out.status.success() {
        return Err(format!("docker run failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(name)
}

/// Run a shell command inside the reservation's sandbox. The container is Linux,
/// so commands are interpreted by `/bin/sh` regardless of the provider host OS.
pub fn exec_in(res: &ComputeReservation, command: &str) -> Result<Output, String> {
    let name = ensure_container(res)?;
    std::process::Command::new("docker")
        .args(["exec", &name, "sh", "-c", command])
        .output()
        .map_err(|e| format!("docker exec failed: {e}"))
}

/// Real per-rental usage from `docker stats`. Returns (cpu_pct_of_rental,
/// ram_used_gb, gpu_pct). CPU is normalised to the rented core count so the
/// gauge reads 0-100% of *what the renter paid for*.
pub fn metrics(res: &ComputeReservation) -> Option<(f32, f64, i32)> {
    let name = container_name(&res.reservation_id);
    if !container_running(&name) {
        return None;
    }
    let out = std::process::Command::new("docker")
        .args(["stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", &name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let line = line.trim();
    let (cpu_raw, mem_part) = line.split_once('|')?;

    // CPUPerc is "123.4%", where 100% == one core. Normalise to rented cores.
    let cpu_total = cpu_raw.trim().trim_end_matches('%').parse::<f32>().unwrap_or(0.0);
    let cpu = (cpu_total / res.cpu_cores.max(1) as f32).clamp(0.0, 100.0);

    // MemUsage is "1.23GiB / 13GiB" — take the used side, convert to GB.
    let used = mem_part.split('/').next().unwrap_or("").trim();
    let ram_used_gb = parse_mem_to_gb(used).min(res.ram_gb as f64);

    // GPU utilisation is host-level (the GPU is dedicated to this container when
    // rented), surfaced via nvidia-smi. Per-process GPU accounting is not done.
    let gpu = if res.gpu_count > 0 {
        std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"])
            .output().ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().lines().next()
                .and_then(|l| l.trim().parse::<i32>().ok()))
            .unwrap_or(0)
    } else {
        0
    };
    Some((cpu, ram_used_gb, gpu))
}

fn parse_mem_to_gb(s: &str) -> f64 {
    let s = s.trim();
    let split = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num.trim().parse().unwrap_or(0.0);
    match unit.trim().to_ascii_lowercase().as_str() {
        "b"               => n / 1_073_741_824.0,
        "kib" | "kb"      => n / 1_048_576.0,
        "mib" | "mb"      => n / 1024.0,
        "gib" | "gb"      => n,
        "tib" | "tb"      => n * 1024.0,
        _                 => n / 1024.0, // docker default is MiB when unitless
    }
}

/// Restrict an uploaded/downloaded name to a flat, safe filename under
/// /workspace — no path separators, no `..`, only `[A-Za-z0-9._-]`.
fn safe_filename(rel: &str) -> String {
    let base = rel.rsplit(['/', '\\']).next().unwrap_or(rel);
    let cleaned: String = base.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_start_matches(['.', '-']).to_string();
    if trimmed.is_empty() { "file".to_string() } else { trimmed }
}

/// Write bytes into the reservation's workspace (`/workspace/<name>`), creating
/// the sandbox if needed. Used for renter file uploads.
pub fn put_file(res: &ComputeReservation, rel: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let name = ensure_container(res)?;
    let fname = safe_filename(rel);
    let mut child = std::process::Command::new("docker")
        .args(["exec", "-i", &name, "sh", "-c", &format!("cat > /workspace/{fname}")])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("docker exec spawn failed: {e}"))?;
    child.stdin.take().ok_or("no stdin handle")?
        .write_all(bytes).map_err(|e| format!("stream to sandbox failed: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("docker exec wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("write failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// Read a file back out of the reservation's workspace. Used for downloading
/// results. Returns the raw bytes.
pub fn get_file(res: &ComputeReservation, rel: &str) -> Result<Vec<u8>, String> {
    let name = container_name(&res.reservation_id);
    if !container_running(&name) {
        return Err("sandbox is not running".into());
    }
    let fname = safe_filename(rel);
    let out = std::process::Command::new("docker")
        .args(["exec", &name, "sh", "-c", &format!("cat /workspace/{fname}")])
        .output()
        .map_err(|e| format!("docker exec failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("read failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(out.stdout)
}

/// Append bytes to a workspace file (used for chunked uploads after the first
/// chunk, which uses `put_file` to truncate/create).
pub fn append_file(res: &ComputeReservation, rel: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let name = ensure_container(res)?;
    let fname = safe_filename(rel);
    let mut child = std::process::Command::new("docker")
        .args(["exec", "-i", &name, "sh", "-c", &format!("cat >> /workspace/{fname}")])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("docker exec spawn failed: {e}"))?;
    child.stdin.take().ok_or("no stdin handle")?
        .write_all(bytes).map_err(|e| format!("stream to sandbox failed: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("docker exec wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("append failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// Read a byte range [offset, offset+len) from a workspace file, for chunked
/// downloads. Uses tail/head so it works on the slim base image.
pub fn read_range(res: &ComputeReservation, rel: &str, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let name = container_name(&res.reservation_id);
    if !container_running(&name) {
        return Err("sandbox is not running".into());
    }
    let fname = safe_filename(rel);
    let script = format!("tail -c +{} /workspace/{} | head -c {}", offset + 1, fname, len);
    let out = std::process::Command::new("docker")
        .args(["exec", &name, "sh", "-c", &script])
        .output()
        .map_err(|e| format!("docker exec failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("read failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(out.stdout)
}

/// Host port that a published container port maps to (e.g. container 8888 →
/// 127.0.0.1:49xxx). Returns None if the port isn't published or no sandbox.
/// Foundation for the in-browser tunnel; harmless until that ships.
pub fn mapped_port(reservation_id: &str, container_port: u16) -> Option<u16> {
    let name = container_name(reservation_id);
    let out = std::process::Command::new("docker")
        .args(["port", &name, &container_port.to_string()])
        .output().ok()?;
    if !out.status.success() { return None; }
    // Output like "127.0.0.1:49153" (possibly several lines).
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().rsplit(':').next().and_then(|p| p.trim().parse::<u16>().ok()))
}

/// List files in the reservation's workspace as (name, size_bytes).
pub fn list_files(res: &ComputeReservation) -> Result<Vec<(String, u64)>, String> {
    let name = container_name(&res.reservation_id);
    if !container_running(&name) {
        return Err("sandbox is not running".into());
    }
    let script = "cd /workspace 2>/dev/null && for f in *; do [ -f \"$f\" ] && printf '%s\\t%s\\n' \"$(wc -c < \"$f\")\" \"$f\"; done";
    let out = std::process::Command::new("docker")
        .args(["exec", &name, "sh", "-c", script])
        .output()
        .map_err(|e| format!("docker exec failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("list failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let mut files = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((size, fname)) = line.split_once('\t') {
            files.push((fname.to_string(), size.trim().parse::<u64>().unwrap_or(0)));
        }
    }
    Ok(files)
}

fn host_workspace_dir(res: &ComputeReservation) -> std::path::PathBuf {
    let short = &res.reservation_id[..8.min(res.reservation_id.len())];
    #[cfg(windows)]
    let base = std::path::PathBuf::from(std::env::var("TEMP").unwrap_or_else(|_| "C:\\Temp".into()));
    #[cfg(not(windows))]
    let base = std::path::PathBuf::from("/tmp");
    base.join("ego_ws").join(short)
}

pub fn put_file_host(res: &ComputeReservation, rel: &str, bytes: &[u8]) -> Result<(), String> {
    let dir = host_workspace_dir(res);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(safe_filename(rel)), bytes).map_err(|e| e.to_string())
}

pub fn append_file_host(res: &ComputeReservation, rel: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let dir = host_workspace_dir(res);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new().append(true).create(true)
        .open(dir.join(safe_filename(rel))).map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| e.to_string())
}

pub fn get_file_host(res: &ComputeReservation, rel: &str) -> Result<Vec<u8>, String> {
    std::fs::read(host_workspace_dir(res).join(safe_filename(rel))).map_err(|e| e.to_string())
}

pub fn read_range_host(res: &ComputeReservation, rel: &str, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let bytes = get_file_host(res, rel)?;
    let start = offset as usize;
    let end = (offset + len).min(bytes.len() as u64) as usize;
    if start >= bytes.len() { return Ok(vec![]); }
    Ok(bytes[start..end].to_vec())
}

pub fn list_files_host(res: &ComputeReservation) -> Result<Vec<(String, u64)>, String> {
    let dir = host_workspace_dir(res);
    if !dir.exists() { return Ok(vec![]); }
    let mut files = vec![];
    for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
        if let Ok(entry) = entry {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    files.push((entry.file_name().to_string_lossy().into_owned(), meta.len()));
                }
            }
        }
    }
    Ok(files)
}

/// Tear down a reservation's container and its workspace volume.
pub fn destroy(reservation_id: &str) {
    if !docker_available() { return; }
    let name = container_name(reservation_id);
    let _ = std::process::Command::new("docker").args(["rm", "-f", &name]).output();
    let _ = std::process::Command::new("docker").args(["volume", "rm", "-f", &volume_name(reservation_id)]).output();
}

/// Remove sandboxes whose reservation is no longer active (terminated, expired,
/// or unknown). Called periodically so cleanup is robust to missed gossip.
pub fn reap_inactive() {
    if !docker_available() { return; }
    let out = match std::process::Command::new("docker")
        .args(["ps", "-a", "--filter", "name=ego-rent-", "--format", "{{.Names}}"])
        .output() {
        Ok(o) if o.status.success() => o,
        _ => return,
    };
    let names = String::from_utf8_lossy(&out.stdout);
    let now = chrono::Utc::now().timestamp();
    for name in names.lines().map(str::trim).filter(|n| !n.is_empty()) {
        // ego-rent-<reservation_id>  (volumes have the -ws suffix, not listed here)
        let res_id = match name.strip_prefix("ego-rent-") {
            Some(id) => id,
            None => continue,
        };
        let active = crate::chain_db::get_compute_reservation(res_id)
            .map(|r| r.status == "active" && r.expires_at > now)
            .unwrap_or(false);
        if !active {
            destroy(res_id);
        }
    }
}
