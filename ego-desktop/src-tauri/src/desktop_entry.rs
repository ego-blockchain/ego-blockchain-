#[cfg(target_os = "linux")]
const MARKER: &str = ".desktop_launcher_done";
#[cfg(target_os = "linux")]
const ENTRY_NAME: &str = "ego-desktop.desktop";

#[cfg(any(target_os = "linux", test))]
pub fn entry_text(exec: &str, icon: &str) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=Ego Desktop\nComment=Quantum-Safe Blockchain Desktop App\nExec=\"{}\" %U\nIcon={}\nTerminal=false\nCategories=Network;Finance;\nStartupWMClass=ego-desktop\n",
        exec.replace('"', "\\\""),
        icon
    )
}

#[cfg(target_os = "linux")]
pub fn ensure_launchers() {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    let marker = crate::ledger::base_data_dir().join(MARKER);
    if marker.exists() {
        return;
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return };
    let appimage = std::env::var_os("APPIMAGE").map(PathBuf::from);
    let exec = match &appimage {
        Some(p) => p.clone(),
        None => match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return,
        },
    };
    let exec = exec.to_string_lossy().to_string();

    let icon = if appimage.is_some() {
        let dir = home.join(".local/share/icons/hicolor/128x128/apps");
        let path = dir.join("ego-desktop.png");
        if std::fs::create_dir_all(&dir).is_ok() {
            let _ = std::fs::write(&path, include_bytes!("../icons/128x128.png"));
        }
        path.to_string_lossy().to_string()
    } else {
        "ego-desktop".to_string()
    };
    let text = entry_text(&exec, &icon);

    if appimage.is_some() {
        let apps = home.join(".local/share/applications");
        if std::fs::create_dir_all(&apps).is_ok() && std::fs::write(apps.join(ENTRY_NAME), &text).is_ok() {
            let _ = std::process::Command::new("update-desktop-database").arg(&apps).status();
            eprintln!("[Desktop] added Ego Desktop to the applications menu");
        }
    }

    let desktop = std::process::Command::new("xdg-user-dir")
        .arg("DESKTOP")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty() && *p != home)
        .unwrap_or_else(|| home.join("Desktop"));
    if desktop.is_dir() {
        let path = desktop.join(ENTRY_NAME);
        if std::fs::write(&path, &text).is_ok() {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
            let _ = std::process::Command::new("gio")
                .args(["set", &path.to_string_lossy(), "metadata::trusted", "true"])
                .status();
            eprintln!("[Desktop] put an Ego Desktop launcher on the desktop");
        }
    }
    let _ = std::fs::write(&marker, env!("CARGO_PKG_VERSION"));
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_launchers() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launcher_quotes_paths_with_spaces_and_opens_without_a_terminal() {
        let text = entry_text("/home/ana/Apps/Ego Desktop.AppImage", "ego-desktop");
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(text.contains("Exec=\"/home/ana/Apps/Ego Desktop.AppImage\" %U\n"));
        assert!(text.contains("Terminal=false\n"));
        assert!(text.contains("Type=Application\n"));
        assert!(text.contains("Icon=ego-desktop\n"));
    }
}
