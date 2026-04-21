use std::collections::{HashMap, HashSet};
use std::process::Child;
use std::sync::{Mutex, OnceLock};

struct FlaskProcess {
    port: u16,
    _child: Child,
    log_path: std::path::PathBuf,
}

static PROCESSES: OnceLock<Mutex<HashMap<String, FlaskProcess>>> = OnceLock::new();

static TRUSTED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn trust_store() -> &'static Mutex<HashSet<String>> {
    TRUSTED.get_or_init(|| Mutex::new(HashSet::new()))
}

pub fn is_python_trusted(site_name: &str) -> bool {
    trust_store().lock().unwrap_or_else(|e| e.into_inner()).contains(site_name)
}

pub fn trust_python_site(site_name: &str) {
    trust_store().lock().unwrap_or_else(|e| e.into_inner()).insert(site_name.to_string());
}

pub fn revoke_python_trust(site_name: &str) {
    trust_store().lock().unwrap_or_else(|e| e.into_inner()).remove(site_name);
}

fn store() -> &'static Mutex<HashMap<String, FlaskProcess>> {
    PROCESSES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Clone)]
pub enum StartupState {
    Starting,
    Ready(u16),
    Failed(String),
}

static STARTUP: OnceLock<Mutex<HashMap<String, StartupState>>> = OnceLock::new();

fn startup_store() -> &'static Mutex<HashMap<String, StartupState>> {
    STARTUP.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn get_startup_state(name: &str) -> Option<StartupState> {
    startup_store().lock().unwrap_or_else(|e| e.into_inner())
        .get(name).cloned()
}

fn set_startup_state(name: &str, state: StartupState) {
    startup_store().lock().unwrap_or_else(|e| e.into_inner())
        .insert(name.to_string(), state);
}

pub fn is_python_site(dir: &std::path::Path) -> bool {
    ["app.py", "main.py", "wsgi.py", "run.py", "requirements.txt"]
        .iter()
        .any(|f| dir.join(f).exists())
}

pub fn site_port(name: &str) -> u16 {
    let h: u32 = name
        .bytes()
        .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32));
    47500 + (h % 500) as u16
}

fn find_python() -> Option<String> {
    let candidates = [
        r"D:\Python312\python.exe",
        r"D:\Python311\python.exe",
        r"D:\Python310\python.exe",
        "python3.12",
        "python3.11",
        "python3.10",
        "python3",
        "python",
    ];
    for c in &candidates {
        if std::process::Command::new(c)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
        {
            return Some(c.to_string());
        }
    }
    None
}

pub fn get_running_port(name: &str) -> Option<u16> {
    store()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(name)
        .map(|p| p.port)
}

/// Fire-and-forget: start Flask in the background and update StartupState.
/// Returns immediately. Callers should poll get_startup_state().
pub fn launch_background(site_name: &str, site_dir: &std::path::Path) {
    // Already running or starting — don't double-launch
    {
        let s = startup_store().lock().unwrap_or_else(|e| e.into_inner());
        if matches!(s.get(site_name), Some(StartupState::Starting) | Some(StartupState::Ready(_))) {
            return;
        }
    }
    set_startup_state(site_name, StartupState::Starting);
    let name = site_name.to_string();
    let dir  = site_dir.to_path_buf();
    tokio::spawn(async move {
        match ensure_running(&name, &dir).await {
            Ok(port) => set_startup_state(&name, StartupState::Ready(port)),
            Err(e)   => {
                store().lock().unwrap_or_else(|e2| e2.into_inner()).remove(&name);
                set_startup_state(&name, StartupState::Failed(e));
            }
        }
    });
}

fn log_path_for(site_dir: &std::path::Path) -> std::path::PathBuf {
    site_dir.join("__ego_flask.log")
}

pub fn ensure_running<'a>(
    site_name: &'a str,
    site_dir: &'a std::path::Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u16, String>> + Send + 'a>> {
    Box::pin(ensure_running_inner(site_name, site_dir))
}

async fn ensure_running_inner(
    site_name: &str,
    site_dir: &std::path::Path,
) -> Result<u16, String> {
    let port = site_port(site_name);

    {
        let guard = store().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(proc) = guard.get(site_name) {
            return Ok(proc.port);
        }
    }

    let python =
        find_python().ok_or_else(|| "Python not found. Install Python 3.x.".to_string())?;

    let entry_owned: String;
    let entry: &str = if let Some(name) = ["app.py", "main.py", "wsgi.py", "run.py"]
        .iter()
        .find(|f| site_dir.join(f).exists())
        .copied()
    {
        name
    } else {
        // Fall back: any .py file in the root that contains Flask(
        let found = std::fs::read_dir(site_dir)
            .ok()
            .and_then(|entries| {
                entries.filter_map(|e| e.ok()).find(|e| {
                    let p = e.path();
                    p.extension().and_then(|x| x.to_str()) == Some("py")
                        && find_flask_app_var(&p).is_some()
                })
            });
        match found {
            Some(e) => {
                entry_owned = e.file_name().to_string_lossy().into_owned();
                eprintln!("[PythonHost] Auto-detected entry point: {}", entry_owned);
                &entry_owned
            }
            None => return Err(
                "No Flask entry point found. Add app.py/main.py or name your file app.py.".to_string()
            ),
        }
    };

    // Build FLASK_APP spec: prefer explicit var name so Flask finds the app
    // regardless of what the variable is called.
    let module_name = entry.trim_end_matches(".py");
    let flask_app_spec = match find_flask_app_var(&site_dir.join(entry)) {
        Some(var) => {
            eprintln!("[PythonHost] Found Flask app var '{}' in {}", var, entry);
            format!("{}:{}", module_name, var)
        }
        None => {
            eprintln!("[PythonHost] No Flask var found in {}, using module name", entry);
            module_name.to_string()
        }
    };

    let log_file = log_path_for(site_dir);
    let log_handle = std::fs::File::create(&log_file)
        .map_err(|e| format!("Cannot create log file: {e}"))?;
    let log_stderr = log_handle.try_clone()
        .map_err(|e| format!("Cannot clone log handle: {e}"))?;

    eprintln!("[PythonHost] Starting '{}' ({}) on :{} — log: {:?}", site_name, entry, port, log_file);

    let mut cmd = std::process::Command::new(&python);
    cmd.args([
        "-m", "flask", "run",
        "--host", "127.0.0.1",
        "--port", &port.to_string(),
        "--no-debugger",
        "--no-reload",
    ])
    .current_dir(site_dir)
    .env("FLASK_APP", &flask_app_spec)
    .env("FLASK_ENV", "production")
    .env("FLASK_DEBUG", "0")
    .env("FLASK_RUN_PORT", port.to_string())
    .stdout(log_handle)
    .stderr(log_stderr);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;

    store()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(site_name.to_string(), FlaskProcess {
            port,
            _child: child,
            log_path: log_file.clone(),
        });

    let timeout_secs = {
        let req_txt_path = site_dir.join("requirements.txt");
        let req_lines = req_txt_path.exists()
            .then(|| std::fs::read_to_string(&req_txt_path).unwrap_or_default().lines().count())
            .unwrap_or(0);
        if req_lines > 10 { 90 } else { 30 }
    };
    match wait_for_port_or_crash(port, site_name, &log_file, timeout_secs).await {
        Ok(()) => {
            eprintln!("[PythonHost] '{}' ready on port {}", site_name, port);
            Ok(port)
        }
        Err(ref e) if e.contains("ModuleNotFoundError") || e.contains("ImportError") => {
            store().lock().unwrap_or_else(|e2| e2.into_inner()).remove(site_name);
            Err(format!(
                "Missing module detected. For security reasons, automatic 'pip install' is disabled in production. \
                Please ensure all dependencies are pre-installed or use an isolated environment. Details: {}", e
            ))
        }
        Err(e) => {
            store().lock().unwrap_or_else(|e2| e2.into_inner()).remove(site_name);
            Err(e)
        }
    }
}

async fn wait_for_port_or_crash(
    port: u16,
    site_name: &str,
    log_path: &std::path::Path,
    timeout_secs: u64,
) -> Result<(), String> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if tokio::time::Instant::now() >= deadline {
            let log = read_log_tail(log_path, 20);
            return Err(format!(
                "Flask '{}' did not start on port {} within {}s.\nLog:\n{}",
                site_name, port, timeout_secs, log
            ));
        }
        let connect = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)),
        ).await;
        if matches!(connect, Ok(Ok(_))) {
            return Ok(());
        }
        // Check if process already exited (crash)
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let log = read_log_tail(log_path, 5);
        if log.contains("Traceback")
            || log.contains("ModuleNotFoundError")
            || log.contains("ImportError")
            || log.contains("Exception:")
            || log.contains("raise Exception")
            || log.contains("SystemExit")
            || (log.contains("Error") && !log.contains("Running on"))
        {
            let full = read_log_tail(log_path, 50);
            return Err(format!("Flask '{}' crashed on startup:\n{}", site_name, full));
        }
    }
}

fn read_log_tail(path: &std::path::Path, lines: usize) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .rev()
        .take(lines)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

/// Scan a Python file for `<var> = Flask(` and return the variable name.
/// Handles any app name, decorators, and factory patterns.
fn find_flask_app_var(path: &std::path::Path) -> Option<String> {
    let src = std::fs::read_to_string(path).ok()?;
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with('#') { continue; }
        let eq_pos = match t.find(" = Flask(").or_else(|| t.find("=Flask(")) {
            Some(p) => p,
            None    => continue,
        };
        let var_part = t[..eq_pos].trim();
        if !var_part.is_empty()
            && var_part.chars().all(|c| c.is_alphanumeric() || c == '_')
            && var_part.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
        {
            return Some(var_part.to_string());
        }
    }
    None
}

fn pip_error_line(stderr: &[u8], stdout: &[u8]) -> String {
    let detail = if !stderr.is_empty() {
        String::from_utf8_lossy(stderr).into_owned()
    } else {
        String::from_utf8_lossy(stdout).into_owned()
    };
    detail
        .lines()
        .find(|l| {
            let lo = l.to_lowercase();
            lo.contains("error") || lo.contains("no space") || lo.contains("could not")
        })
        .unwrap_or_else(|| detail.lines().last().unwrap_or("unknown"))
        .trim()
        .to_string()
}

pub fn stop_all() {
    let mut guard = store().lock().unwrap_or_else(|e| e.into_inner());
    for (name, mut proc) in guard.drain() {
        eprintln!("[PythonHost] Stopping '{}'", name);
        let _ = proc._child.kill();
        let _ = std::fs::remove_file(&proc.log_path);
    }
}

pub fn stop(site_name: &str) {
    let mut guard = store().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut proc) = guard.remove(site_name) {
        let _ = proc._child.kill();
        let _ = std::fs::remove_file(&proc.log_path);
    }
}

pub fn get_log(site_name: &str) -> String {
    let guard = store().lock().unwrap_or_else(|e| e.into_inner());
    guard.get(site_name)
        .map(|p| read_log_tail(&p.log_path, 50))
        .unwrap_or_default()
}
