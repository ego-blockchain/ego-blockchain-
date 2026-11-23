use once_cell::sync::OnceCell;
use tauri::Manager;

static HANDLE: OnceCell<tauri::AppHandle> = OnceCell::new();

pub const RESTART_EXIT_CODE: i32 = 75;

pub fn set_handle(handle: tauri::AppHandle) {
    let _ = HANDLE.set(handle);
}

pub fn handle() -> Option<&'static tauri::AppHandle> {
    HANDLE.get()
}

pub fn emit_all<S: serde::Serialize + Clone>(event: &str, payload: S) {
    if let Some(h) = handle() {
        let _ = h.emit_all(event, payload);
    }
}

pub fn notify(title: &str, body: &str) {
    match handle() {
        Some(h) => crate::commands::notifications::notify(h, title, body),
        None => eprintln!("[Notice] {title}: {body}"),
    }
}

pub fn restart() {
    if let Some(h) = handle() {
        h.restart();
    }
    eprintln!("[Node] stopping so it can start again; a service manager restarts it on its own");
    std::process::exit(RESTART_EXIT_CODE);
}
