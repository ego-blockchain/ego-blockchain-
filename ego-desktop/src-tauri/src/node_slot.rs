use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

pub const NODES_PER_COMPUTER: usize = 2;
const RETRY_SECS: i64 = 30;

static HELD: Mutex<Option<File>> = Mutex::new(None);
static LAST_TRY: AtomicI64 = AtomicI64::new(i64::MIN);
static BLOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn slots_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("EGO_NODE_SLOTS_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("EgoDesktop")
            .join("node-slots")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Users/Shared/EgoDesktop/node-slots")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/tmp/ego-node-slots")
    }
}

fn try_take(dir: &std::path::Path) -> Result<File, bool> {
    if std::fs::create_dir_all(dir).is_err() {
        return Err(false);
    }
    let mut busy = 0;
    for i in 1..=NODES_PER_COMPUTER {
        let path = dir.join(format!("slot-{i}.lock"));
        let Ok(file) = OpenOptions::new().create(true).read(true).write(true).open(&path) else { continue };
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => busy += 1,
        }
    }
    Err(busy >= NODES_PER_COMPUTER)
}

pub fn holds_slot() -> bool {
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if held.is_some() {
        return true;
    }
    let now = chrono::Utc::now().timestamp();
    let last = LAST_TRY.load(Ordering::Relaxed);
    if last != i64::MIN && now.saturating_sub(last) < RETRY_SECS {
        return !BLOCKED.load(Ordering::Relaxed);
    }
    LAST_TRY.store(now, Ordering::Relaxed);
    match try_take(&slots_dir()) {
        Ok(file) => {
            *held = Some(file);
            BLOCKED.store(false, Ordering::Relaxed);
            true
        }
        Err(all_busy) => {
            BLOCKED.store(all_busy, Ordering::Relaxed);
            !all_busy
        }
    }
}

pub fn blocked_reason() -> Option<String> {
    (!holds_slot()).then(|| {
        format!("{NODES_PER_COMPUTER} Ego nodes already run on this computer, the most one computer may run. Close one of them and this one starts earning.")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_third_node_on_one_computer_finds_every_place_taken() {
        let dir = std::env::temp_dir().join(format!("ego-slots-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = try_take(&dir).expect("the first node gets a place");
        let second = try_take(&dir).expect("the second node gets a place");
        assert_eq!(try_take(&dir).err(), Some(true), "a third node is refused");
        drop(first);
        let third = try_take(&dir).expect("a place frees up when a node closes");
        drop((second, third));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
