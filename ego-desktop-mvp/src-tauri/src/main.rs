// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod commands;
mod config;
mod crypto;
mod database;
mod error;
mod ledger;
mod models;
mod p2p;
mod services;
mod utils;

use tauri::{Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem};
use tauri::{CustomMenuItem, Menu, MenuItem, Submenu};

fn acquire_single_instance_lock() -> Option<std::net::TcpListener> {
    match std::net::TcpListener::bind("127.0.0.1:47391") {
        Ok(l) => Some(l),
        Err(_) => {
            eprintln!("[Ego Desktop] Another instance may already be running.");
            None
        }
    }
}

#[cfg(target_os = "windows")]
unsafe fn winapi_msgbox(title: *const u16, msg: *const u16) {
    let lib = windows_sys_call(b"user32.dll\0", b"MessageBoxW\0");
    if let Some(f) = lib {
        type MsgBoxW = unsafe extern "system" fn(*mut std::ffi::c_void, *const u16, *const u16, u32) -> i32;
        let f: MsgBoxW = std::mem::transmute(f);
        f(std::ptr::null_mut(), msg, title, 0x30);
    }
}

#[cfg(target_os = "windows")]
unsafe fn windows_sys_call(lib: &[u8], _func: &[u8]) -> Option<*const ()> {
    let _ = (lib, _func);
    None
}

fn main() {
    let _instance_lock = acquire_single_instance_lock();

    // ── System tray ────────────────────────────────────────────────────────
    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    let hide = CustomMenuItem::new("hide".to_string(), "Hide");
    let show = CustomMenuItem::new("show".to_string(), "Show");
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(hide)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);
    let tray = SystemTray::new().with_menu(tray_menu);

    // ── App menu ───────────────────────────────────────────────────────────
    let submenu = Submenu::new(
        "Ego Desktop",
        Menu::new()
            .add_native_item(MenuItem::About(
                "Ego Desktop".to_string(),
                tauri::AboutMetadata::new(),
            ))
            .add_native_item(MenuItem::Separator)
            .add_native_item(MenuItem::Services)
            .add_native_item(MenuItem::Separator)
            .add_native_item(MenuItem::Hide)
            .add_native_item(MenuItem::HideOthers)
            .add_native_item(MenuItem::ShowAll)
            .add_native_item(MenuItem::Separator)
            .add_native_item(MenuItem::Quit),
    );
    let menu = Menu::new()
        .add_submenu(submenu)
        .add_submenu(Submenu::new(
            "File",
            Menu::new().add_native_item(MenuItem::CloseWindow),
        ))
        .add_submenu(Submenu::new(
            "Edit",
            Menu::new()
                .add_native_item(MenuItem::Undo)
                .add_native_item(MenuItem::Redo)
                .add_native_item(MenuItem::Separator)
                .add_native_item(MenuItem::Cut)
                .add_native_item(MenuItem::Copy)
                .add_native_item(MenuItem::Paste)
                .add_native_item(MenuItem::SelectAll),
        ))
        .add_submenu(Submenu::new(
            "View",
            Menu::new().add_native_item(MenuItem::EnterFullScreen),
        ))
        .add_submenu(Submenu::new(
            "Window",
            Menu::new()
                .add_native_item(MenuItem::Minimize)
                .add_native_item(MenuItem::Zoom),
        ));

    tauri::Builder::default()
        .manage(app::AppState::new())
        .system_tray(tray)
        .menu(menu)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { .. } => {
                let window = app.get_window("main").unwrap();
                if window.is_visible().unwrap() {
                    window.hide().unwrap();
                } else {
                    window.show().unwrap();
                    window.set_focus().unwrap();
                }
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => std::process::exit(0),
                "hide" => {
                    let window = app.get_window("main").unwrap();
                    window.hide().unwrap();
                }
                "show" => {
                    let window = app.get_window("main").unwrap();
                    window.show().unwrap();
                    window.set_focus().unwrap();
                }
                _ => {}
            },
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            // Auth / wallet init
            commands::auth::init_wallet,
            commands::auth::generate_keypair,
            commands::auth::import_keypair,
            commands::auth::get_address,
            // Multi-wallet management
            commands::auth::list_wallets,
            commands::auth::create_wallet,
            commands::auth::switch_wallet,
            commands::auth::delete_wallet,
            commands::auth::rename_wallet,
            // Security / recovery
            commands::auth::set_security_pin,
            commands::auth::verify_pin,
            commands::auth::get_recovery_info,
            // Wallet
            commands::wallet::get_balance,
            commands::wallet::send_transaction,
            commands::wallet::get_transaction_history,
            commands::wallet::reset_chain,
            // Storage
            commands::storage::store_file,
            commands::storage::get_stored_files,
            commands::storage::get_storage_metrics,
            commands::storage::configure_storage,
            commands::storage::delete_stored_file,
            commands::storage::retrieve_file_preview,
            // Files (legacy EgoSafe)
            commands::files::encrypt_file,
            commands::files::decrypt_file,
            // Coverage / earnings / staking
            commands::coverage::get_coverage_status,
            commands::coverage::get_poc_events,
            commands::coverage::get_network_peers,
            commands::earnings::get_earnings_data,
            commands::staking::get_staking_info,
            // Explorer
            commands::explorer::get_network_stats,
            commands::explorer::get_p2p_status,
            commands::explorer::get_blocks,
            commands::explorer::get_all_transactions,
            commands::explorer::get_block_info,
            commands::explorer::get_transaction_info,
            commands::explorer::get_file_events,
            // Notifications / sharing
            commands::notifications::import_shared_file,
            // Messenger
            commands::messenger::get_my_contact_bundle,
            commands::messenger::import_contact,
            commands::messenger::approve_contact_request,
            commands::messenger::decline_contact_request,
            commands::messenger::get_contacts,
            commands::messenger::send_message,
            commands::messenger::receive_message,
            commands::messenger::get_messages,
            commands::messenger::delete_contact,
            commands::messenger::clear_messages,
        ])
        .setup(|app| {
            // ── 1. Start the libp2p swarm ──────────────────────────────────
            // This connects to the relay and begins the reservation handshake.
            // Nothing else should fire until the relay circuit is ready.
            let handle_p2p = app.handle();
            tauri::async_runtime::spawn(async move {
                crate::p2p::start_p2p_server(handle_p2p).await;
            });

            // ── 2. Startup sync + announce sequence ────────────────────────
            //
            // OLD problem: fired after 3 s → relay not ready → stale LAN
            // endpoints used → all broadcasts time out silently.
            //
            // FIX: wait_for_public_endpoint(15) blocks until we have a relay
            // circuit address (or 15 s timeout). Only then do we announce
            // ourselves and sync the chain, so peers receive our current
            // relay endpoint and can dial us back through the relay.
            let handle_startup = app.handle();
            tauri::async_runtime::spawn(async move {
                // Block until relay circuit address is confirmed (max 15 s).
                // After the p2p fix this typically takes 2–4 s.
                let my_endpoint = crate::p2p::wait_for_public_endpoint(30).await;

                if my_endpoint.is_empty() {
                    eprintln!("[Startup] No public endpoint after 15s — running in local-only mode");
                } else {
                    eprintln!("[Startup] Public endpoint ready: {}", my_endpoint);
                }

                // Fetch the global chain from the relay seed node.
                // This ensures every node starts with the full shared history
                // even on a fresh install, before any P2P peer connections.
                crate::p2p::fetch_chain_from_relay(&handle_startup).await;
                eprintln!("[Startup] Relay chain sync complete");

                // Announce our (now relay-circuit) endpoint to all contacts.
                // This refreshes their stale stored endpoint for us.
                crate::p2p::broadcast_peer_announce(&handle_startup).await;
                eprintln!("[Startup] Peer announce sent");

                // Small gap so the announce arrives before the sync request,
                // giving peers a chance to update our endpoint first.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                // Request full chain sync from all reachable peers.
                // Uses fresh relay endpoints (announce above may have just
                // triggered a PeerAnnounce response that refreshed their addr).
                crate::p2p::sync_chain_from_peers().await;
                eprintln!("[Startup] Chain sync requested");

                // ── 3. Periodic keep-alive loop ────────────────────────────
                // Re-announce and re-sync every 30 s to:
                //   - Keep relay reservation alive (relay drops idle circuits)
                //   - Pick up any txs that arrived while we were offline
                //   - Refresh peer endpoints if a contact reconnected via relay
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                    // Re-announce with latest endpoint (relay may have rotated)
                    crate::p2p::broadcast_peer_announce(&handle_startup).await;

                    // Sync chain — uses live peer endpoints from AppState,
                    // so stale contact endpoints are automatically bypassed
                    crate::p2p::sync_chain_from_peers().await;
                }
            });

            #[cfg(debug_assertions)]
            {
                let window = app.get_window("main").unwrap();
                window.open_devtools();
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}