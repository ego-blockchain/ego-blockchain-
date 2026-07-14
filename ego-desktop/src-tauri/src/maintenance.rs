use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

pub static WAKE_LOCK_WANTED: AtomicBool = AtomicBool::new(true);
static PROCESS_STARTED_AT: AtomicI64 = AtomicI64::new(0);

pub fn wake_lock_wanted() -> bool {
    WAKE_LOCK_WANTED.load(Ordering::Relaxed)
}

pub fn init_process_start() {
    PROCESS_STARTED_AT.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
}

fn process_uptime_secs() -> i64 {
    let started = PROCESS_STARTED_AT.load(Ordering::Relaxed);
    if started == 0 { return 0; }
    chrono::Utc::now().timestamp() - started
}

#[cfg(target_os = "windows")]
pub fn on_ac_power() -> bool {
    #[repr(C)]
    struct SystemPowerStatus {
        ac_line_status: u8,
        battery_flag: u8,
        battery_life_percent: u8,
        system_status_flag: u8,
        battery_life_time: u32,
        battery_full_life_time: u32,
    }
    extern "system" {
        fn GetSystemPowerStatus(status: *mut SystemPowerStatus) -> i32;
    }
    let mut status = SystemPowerStatus {
        ac_line_status: 255,
        battery_flag: 0,
        battery_life_percent: 0,
        system_status_flag: 0,
        battery_life_time: 0,
        battery_full_life_time: 0,
    };
    let ok = unsafe { GetSystemPowerStatus(&mut status) };
    if ok == 0 { return true; }
    status.ac_line_status != 0
}

#[cfg(target_os = "macos")]
pub fn on_ac_power() -> bool {
    match std::process::Command::new("pmset").args(["-g", "batt"]).output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            !text.contains("Battery Power")
        }
        Err(_) => true,
    }
}

#[cfg(target_os = "linux")]
pub fn on_ac_power() -> bool {
    let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else { return true; };
    let mut battery_discharging = false;
    let mut mains_online = false;
    let mut saw_mains = false;
    for entry in entries.flatten() {
        let p = entry.path();
        let kind = std::fs::read_to_string(p.join("type")).unwrap_or_default();
        if kind.trim() == "Mains" {
            saw_mains = true;
            if std::fs::read_to_string(p.join("online")).unwrap_or_default().trim() == "1" {
                mains_online = true;
            }
        } else if kind.trim() == "Battery" {
            if std::fs::read_to_string(p.join("status")).unwrap_or_default().trim() == "Discharging" {
                battery_discharging = true;
            }
        }
    }
    if mains_online { return true; }
    if saw_mains { return false; }
    !battery_discharging
}

pub fn start_power_source_watcher() {
    std::thread::spawn(|| {
        let mut last = true;
        loop {
            let ac = on_ac_power();
            WAKE_LOCK_WANTED.store(ac, Ordering::Relaxed);
            if ac != last {
                if ac {
                    eprintln!("[Power] AC power restored — re-acquiring sleep prevention");
                } else {
                    eprintln!("[Power] On battery — releasing sleep prevention to protect the battery (node will pause if the machine sleeps and catch up on wake)");
                }
                last = ac;
            }
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });
}

#[cfg(target_os = "windows")]
pub fn current_rss_mb() -> u64 {
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(process: isize, counters: *mut ProcessMemoryCounters, cb: u32) -> i32;
    }
    let mut c: ProcessMemoryCounters = unsafe { std::mem::zeroed() };
    c.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
    if ok == 0 { return 0; }
    (c.working_set_size / (1024 * 1024)) as u64
}

#[cfg(target_os = "linux")]
pub fn current_rss_mb() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = statm.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    pages * 4096 / (1024 * 1024)
}

#[cfg(target_os = "macos")]
pub fn current_rss_mb() -> u64 {
    let pid = std::process::id().to_string();
    match std::process::Command::new("ps").args(["-o", "rss=", "-p", &pid]).output() {
        Ok(out) => {
            let kb: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0);
            kb / 1024
        }
        Err(_) => 0,
    }
}

fn restart_jitter_secs(address: &str) -> i64 {
    let h = blake3::hash(address.as_bytes());
    let n = u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap_or([0u8; 8]));
    (n % 21_600) as i64
}

fn is_node_busy() -> bool {
    if crate::mempool::get_mempool().pending_count() > 0 { return true; }
    let now = chrono::Utc::now().timestamp();
    let ledger = crate::ledger::Ledger::load();
    ledger.stored_files.iter().any(|f| {
        (f.status == "Pending" || (f.blocks_total > 0 && f.blocks_received < f.blocks_total))
            && f.last_block_at > 0
            && now - f.last_block_at < 300
    })
}

pub fn start_health_watchdog(app: tauri::AppHandle) {
    let max_rss_mb: u64 = std::env::var("EGO_MAX_RSS_MB")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(3072);
    let max_uptime_days: i64 = std::env::var("EGO_RESTART_AFTER_DAYS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(7);

    std::thread::spawn(move || {
        let mut deferred_since: Option<i64> = None;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let uptime = process_uptime_secs();
            if uptime < 600 { continue; }

            let rss = current_rss_mb();
            let address = crate::ledger::Ledger::load().address;
            let max_uptime = max_uptime_days * 86_400 + restart_jitter_secs(&address);

            let reason = if max_rss_mb > 0 && rss >= max_rss_mb {
                Some(format!("memory {} MB >= limit {} MB", rss, max_rss_mb))
            } else if max_uptime_days > 0 && uptime >= max_uptime {
                Some(format!("uptime {}h >= scheduled maintenance restart", uptime / 3600))
            } else {
                None
            };

            let Some(reason) = reason else { deferred_since = None; continue; };

            let now = chrono::Utc::now().timestamp();
            let waited_too_long = deferred_since.map(|t| now - t > 1_800).unwrap_or(false);
            if is_node_busy() && !waited_too_long {
                if deferred_since.is_none() {
                    deferred_since = Some(now);
                    eprintln!("[Maintenance] Restart needed ({}) — deferred while node is busy", reason);
                }
                continue;
            }

            eprintln!("[Maintenance] Graceful self-restart: {}", reason);
            app.restart();
        }
    });
}
