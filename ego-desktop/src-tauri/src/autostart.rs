use std::path::PathBuf;

const APP_KEY: &str = "EgoDesktop";
const HIDDEN_FLAG: &str = "--hidden";

pub fn launched_hidden() -> bool {
    std::env::args().any(|a| a == HIDDEN_FLAG)
}

fn exe_path() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("cannot resolve executable path: {e}"))
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    fn open(write: bool) -> Result<RegKey, String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let access = if write { KEY_READ | KEY_WRITE } else { KEY_READ };
        hkcu.open_subkey_with_flags(RUN_KEY, access)
            .map_err(|e| format!("cannot open Run key: {e}"))
    }

    pub fn is_enabled() -> bool {
        open(false)
            .and_then(|k| k.get_value::<String, _>(APP_KEY).map_err(|e| e.to_string()))
            .is_ok()
    }

    pub fn enable() -> Result<(), String> {
        let exe = exe_path()?;
        let value = format!("\"{}\" {}", exe.display(), HIDDEN_FLAG);
        open(true)?
            .set_value(APP_KEY, &value)
            .map_err(|e| format!("cannot write Run key: {e}"))
    }

    pub fn disable() -> Result<(), String> {
        match open(true)?.delete_value(APP_KEY) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("cannot delete Run key: {e}")),
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    const LABEL: &str = "com.ego.desktop";

    fn plist_path() -> Result<PathBuf, String> {
        let home = dirs::home_dir().ok_or("cannot resolve home directory")?;
        Ok(home.join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
    }

    pub fn is_enabled() -> bool {
        plist_path().map(|p| p.exists()).unwrap_or(false)
    }

    pub fn enable() -> Result<(), String> {
        let exe = exe_path()?;
        let path = plist_path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("cannot create LaunchAgents: {e}"))?;
        }
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>{}</string><string>{HIDDEN_FLAG}</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
"#,
            exe.display()
        );
        std::fs::write(&path, plist).map_err(|e| format!("cannot write plist: {e}"))
    }

    pub fn disable() -> Result<(), String> {
        let path = plist_path()?;
        if !path.exists() {
            return Ok(());
        }
        std::fs::remove_file(&path).map_err(|e| format!("cannot remove plist: {e}"))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use super::*;

    fn desktop_path() -> Result<PathBuf, String> {
        let cfg = dirs::config_dir().ok_or("cannot resolve config directory")?;
        Ok(cfg.join("autostart").join("ego-desktop.desktop"))
    }

    pub fn is_enabled() -> bool {
        desktop_path().map(|p| p.exists()).unwrap_or(false)
    }

    pub fn enable() -> Result<(), String> {
        let exe = exe_path()?;
        let path = desktop_path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("cannot create autostart dir: {e}"))?;
        }
        let entry = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Ego Desktop\n\
             Exec=\"{}\" {HIDDEN_FLAG}\n\
             Terminal=false\n\
             X-GNOME-Autostart-enabled=true\n",
            exe.display()
        );
        std::fs::write(&path, entry).map_err(|e| format!("cannot write desktop entry: {e}"))
    }

    pub fn disable() -> Result<(), String> {
        let path = desktop_path()?;
        if !path.exists() {
            return Ok(());
        }
        std::fs::remove_file(&path).map_err(|e| format!("cannot remove desktop entry: {e}"))
    }
}

pub fn ensure_enabled_once() {
    let marker = crate::ledger::base_data_dir().join(".autostart_configured");
    if marker.exists() {
        return;
    }
    match imp::enable() {
        Ok(()) => {
            let _ = std::fs::write(&marker, b"1");
            eprintln!("[Autostart] registered to launch at login (hidden)");
        }
        Err(e) => eprintln!("[Autostart] could not register: {e}"),
    }
}

#[tauri::command]
pub fn get_autostart_enabled() -> bool {
    imp::is_enabled()
}

#[tauri::command]
pub fn set_autostart_enabled(enabled: bool) -> Result<bool, String> {
    if enabled {
        imp::enable()?;
    } else {
        imp::disable()?;
    }
    Ok(imp::is_enabled())
}
