use crate::error::{EgoDesktopError, EgoResult};


pub fn os_protect(data: &[u8]) -> Vec<u8> {
    #[cfg(windows)]
    {
        windows_dpapi::protect(data).unwrap_or_else(|_| data.to_vec())
    }
    #[cfg(not(windows))]
    {
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
        data.to_vec()
    }
}

#[cfg(windows)]
mod windows_dpapi {
    use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData};
    use winapi::um::wincrypt::DATA_BLOB;
    use winapi::um::winbase::LocalFree;

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
            if ok == 0 || output.pbData.is_null() { return Err(()); }
            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as *mut _);
            Ok(result)
        }
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, ()> {
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
            if ok == 0 || output.pbData.is_null() { return Err(()); }
            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as *mut _);
            Ok(result)
        }
    }
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
