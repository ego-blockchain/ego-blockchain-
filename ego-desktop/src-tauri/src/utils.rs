use crate::error::{EgoDesktopError, EgoResult};


pub fn os_protect(data: &[u8]) -> Vec<u8> {
    #[cfg(windows)]
    {
        windows_dpapi::protect(data).unwrap_or_else(|_| data.to_vec())
    }
    #[cfg(not(windows))]
    {
        // NEVER write to the Keychain here. This function is called with arbitrary
        // blobs (e.g. the libp2p identity), and the old implementation stored them
        // all into the single "wallet-seed" Keychain item — overwriting the user's
        // wallet seed (the "invalid seed data (68 bytes)" data-loss bug on macOS).
        // The wallet seed has its own dedicated writer in ledger::save_seed.
        data.to_vec()
    }
}

pub fn os_unprotect(data: &[u8]) -> Vec<u8> {
    #[cfg(windows)]
    {
        windows_dpapi::unprotect(data).unwrap_or_else(|_| data.to_vec())
    }
    #[cfg(not(windows))]
    {
        if data == b"ego-keyring-protected" || data == b"ego-keyring-seed-v1" {
            use base64::Engine as _;
            if let Ok(entry) = keyring::Entry::new("ego-desktop", "wallet-seed") {
                if let Ok(pw) = entry.get_password() {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&pw) {
                        return decoded;
                    }
                }
            }
            return Vec::new();
        }
        data.to_vec()
    }
}

#[cfg(windows)]
mod windows_dpapi {
    use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData};
    use winapi::um::wincrypt::DATA_BLOB;
    use winapi::um::winbase::LocalFree;
    use winapi::um::errhandlingapi::GetLastError;

    pub fn describe(code: u32) -> String {
        match code {
            0x8009_000B => "the Windows credential that encrypted it is no longer usable                             (NTE_BAD_KEY_STATE). This normally means the Windows password was                             reset rather than changed, which permanently invalidates the old                             encryption key".to_string(),
            0x8009_0005 => "the stored data failed its integrity check (NTE_BAD_DATA), so the                             file is damaged".to_string(),
            0x8007_000D => "the stored data is not a valid Windows-encrypted blob".to_string(),
            0x8009_0016 => "no encryption key exists for this Windows account (NTE_BAD_KEYSET)".to_string(),
            other => format!("Windows could not decrypt it (DPAPI error 0x{other:08X})"),
        }
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, ()> {
        unsafe {
            let mut input = DATA_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut output = DATA_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
            let ok = CryptProtectData(
                &mut input,
                std::ptr::null(),     // description
                std::ptr::null_mut(), // optional entropy
                std::ptr::null_mut(), // reserved
                std::ptr::null_mut(), // prompt
                0,
                &mut output,
            );
            if ok == 0 { return Err(()); }
            let result = if !output.pbData.is_null() && output.cbData > 0 {
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
            } else {
                Vec::new()
            };
            LocalFree(output.pbData as *mut _);
            Ok(result)
        }
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, u32> {
        unsafe {
            let mut input = DATA_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut output = DATA_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
            let ok = CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(), // description out
                std::ptr::null_mut(), // optional entropy
                std::ptr::null_mut(), // reserved
                std::ptr::null_mut(), // prompt
                0,
                &mut output,
            );
            if ok == 0 { return Err(GetLastError()); }
            let result = if !output.pbData.is_null() && output.cbData > 0 {
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
            } else {
                Vec::new()
            };
            LocalFree(output.pbData as *mut _);
            Ok(result)
        }
    }
}

pub fn os_unprotect_checked(data: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        windows_dpapi::unprotect(data).map_err(windows_dpapi::describe)
    }
    #[cfg(not(windows))]
    {
        let out = os_unprotect(data);
        if out.is_empty() {
            return Err("the OS keyring returned no data".to_string());
        }
        Ok(out)
    }
}

pub fn open_file_limit() -> u64 {
    static LIMIT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(raise_open_file_limit)
}

pub fn open_file_budget(share: u64, floor: u64, ceiling: u64) -> u64 {
    (open_file_limit() / share).clamp(floor, ceiling)
}

#[cfg(unix)]
fn raise_open_file_limit() -> u64 {
    let mut current = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) } != 0 {
        return 256;
    }
    let wanted: libc::rlim_t = if cfg!(target_os = "macos") { 10_240 } else { 65_536 };
    let target = wanted.min(current.rlim_max);
    if current.rlim_cur >= target {
        return current.rlim_cur as u64;
    }
    let raised = libc::rlimit { rlim_cur: target, rlim_max: current.rlim_max };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
        eprintln!("[Startup] open-file limit raised from {} to {}", current.rlim_cur, target);
        target as u64
    } else {
        eprintln!(
            "[Startup] could not raise the open-file limit above {} ({})",
            current.rlim_cur,
            std::io::Error::last_os_error()
        );
        current.rlim_cur as u64
    }
}

#[cfg(not(unix))]
fn raise_open_file_limit() -> u64 {
    16_384
}

pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

pub fn format_balance(amount: u64) -> String {
    let egoc = amount as f64 / 1_000_000.0;
    format!("{:.6} EGOC", egoc)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

pub fn format_timestamp(timestamp: i64) -> String {
    match chrono::DateTime::from_timestamp(timestamp, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Invalid timestamp".to_string(),
    }
}
