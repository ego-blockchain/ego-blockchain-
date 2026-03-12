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

fn main() {
    let _instance_lock = acquire_single_instance_lock();

    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    let hide = CustomMenuItem::new("hide".to_string(), "Hide");
    let show = CustomMenuItem::new("show".to_string(), "Show");
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(hide)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);
    let tray = SystemTray::new().with_menu(tray_menu);

    let submenu = Submenu::new(
        "Ego Desktop",
        Menu::new()
            .add_native_item(MenuItem::About("Ego Desktop".to_string(), tauri::AboutMetadata::new()))
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
        .add_submenu(Submenu::new("File",
            Menu::new().add_native_item(MenuItem::CloseWindow)))
        .add_submenu(Submenu::new("Edit",
            Menu::new()
                .add_native_item(MenuItem::Undo)
                .add_native_item(MenuItem::Redo)
                .add_native_item(MenuItem::Separator)
                .add_native_item(MenuItem::Cut)
                .add_native_item(MenuItem::Copy)
                .add_native_item(MenuItem::Paste)
                .add_native_item(MenuItem::SelectAll)))
        .add_submenu(Submenu::new("View",
            Menu::new().add_native_item(MenuItem::EnterFullScreen)))
        .add_submenu(Submenu::new("Window",
            Menu::new()
                .add_native_item(MenuItem::Minimize)
                .add_native_item(MenuItem::Zoom)));

    tauri::Builder::default()
        .manage(app::AppState::new())
        .system_tray(tray)
        .menu(menu)
        // Intercept window close (Alt+F4, red button fallback) — hide to tray
        // instead of destroying the window.  Destroying the window stops P2P/
        // coverage background tasks; hiding keeps them alive.
        // The only way to actually quit is via the tray "Quit" menu item.
        .on_window_event(|event| {
            match event.event() {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    event.window().hide().unwrap();
                    api.prevent_close();
                }
                tauri::WindowEvent::Focused(true) => {
                    use tauri::Manager;
                    let app_handle = event.window().app_handle();
                    let state = app_handle.state::<app::AppState>();
                    let maybe_addr = state.pending_chat_address.lock().unwrap().take();
                    if let Some(addr) = maybe_addr {
                        let _ = event.window().emit("ego://open-chat", serde_json::json!({ "address": addr }));
                    }
                }
                _ => {}
            }
        })
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { .. } => {
                let window = app.get_window("main").unwrap();
                if window.is_visible().unwrap() { window.hide().unwrap(); }
                else { window.show().unwrap(); window.set_focus().unwrap(); }
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => std::process::exit(0),
                "hide" => app.get_window("main").unwrap().hide().unwrap(),
                "show" => {
                    let w = app.get_window("main").unwrap();
                    w.show().unwrap(); w.set_focus().unwrap();
                }
                _ => {}
            },
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            commands::auth::init_wallet,
            commands::auth::generate_keypair,
            commands::auth::import_keypair,
            commands::auth::get_address,
            commands::auth::list_wallets,
            commands::auth::create_wallet,
            commands::auth::switch_wallet,
            commands::auth::delete_wallet,
            commands::auth::rename_wallet,
            commands::auth::set_security_pin,
            commands::auth::verify_pin,
            commands::auth::get_recovery_info,
            commands::auth::get_pin_status,
            commands::wallet::get_balance,
            commands::wallet::send_transaction,
            commands::wallet::prepare_transaction,
            commands::wallet::commit_transaction,
            commands::wallet::get_transaction_history,
            commands::wallet::reset_chain,
            commands::storage::store_file,
            commands::storage::get_stored_files,
            commands::storage::get_storage_metrics,
            commands::storage::configure_storage,
            commands::storage::delete_stored_file,
            commands::storage::retrieve_file_preview,
            commands::storage::save_file_to_disk,
            commands::storage::request_file_from_contact,
            commands::files::encrypt_file,
            commands::files::decrypt_file,
            commands::coverage::get_coverage_status,
            commands::coverage::get_poc_events,
            commands::coverage::get_network_peers,
            commands::earnings::get_earnings_data,
            commands::staking::get_staking_info,
            commands::staking::stake_coins,
            commands::staking::unstake_coins,
            commands::explorer::get_network_stats,
            commands::explorer::get_p2p_status,
            commands::explorer::get_blocks,
            commands::explorer::get_all_transactions,
            commands::explorer::get_block_info,
            commands::explorer::get_transaction_info,
            commands::explorer::get_file_events,
            commands::notifications::import_shared_file,
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
            commands::messenger::delete_message,
        ])
        .setup(|app| {
            // Show the window only after the frontend signals it's ready,
            // preventing the white-flash / multi-render flicker on startup.
            let window = app.get_window("main").unwrap();
            app.listen_global("frontend-ready", move |_| {
                window.show().unwrap();
                window.set_focus().unwrap();
            });

            // ── Task 1: libp2p swarm ───────────────────────────────────────
            // Connects to relay, handles all P2P traffic.
            let handle_p2p = app.handle();
            tauri::async_runtime::spawn(async move {
                crate::p2p::start_p2p_server(handle_p2p).await;
            });

            // ── Task 2: startup announce + chain sync ──────────────────────
            // Waits for relay circuit before announcing so peers receive our
            // real circuit address (not the raw public IP which is firewalled).
            let handle_startup = app.handle();
            tauri::async_runtime::spawn(async move {
                let my_endpoint = crate::p2p::wait_for_public_endpoint(60).await;

                if my_endpoint.contains("/p2p-circuit") {
                    eprintln!("[Startup] ✓ Relay circuit confirmed: {}", my_endpoint);
                } else if !my_endpoint.is_empty() {
                    eprintln!("[Startup] ⚠ Relay not confirmed in 20s — using: {}", my_endpoint);
                } else {
                    eprintln!("[Startup] ✗ No endpoint — check network");
                }

                crate::p2p::fetch_peers_from_relay(&handle_startup).await;
                eprintln!("[Startup] Relay peer directory synced");

                crate::p2p::fetch_chain_from_relay(&handle_startup).await;
                eprintln!("[Startup] Relay chain sync complete");

                // Fetch any offline messages waiting in relay inbox
                crate::commands::messenger::fetch_relay_inbox(&handle_startup).await;
                eprintln!("[Startup] Relay inbox checked");

                crate::p2p::broadcast_peer_announce(&handle_startup).await;
                eprintln!("[Startup] Peer announce sent (endpoint: {})", my_endpoint);

                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                crate::p2p::sync_chain_from_peers().await;
                eprintln!("[Startup] Chain sync requested");

                // Keep-alive: re-register + re-announce + sync every 30 s.
                // re-register keeps last_seen fresh on the relay so the
                // 10-minute recency filter in fetch_peers_from_relay works.
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                    // Re-register with relay (refreshes last_seen + location).
                    let ledger    = crate::ledger::Ledger::load();
                    let registry  = crate::ledger::load_registry();
                    let active_id = crate::ledger::get_active_wallet_id();
                    let name = registry.wallets.iter()
                        .find(|w| w.id == active_id)
                        .map(|w| w.name.clone())
                        .unwrap_or_else(|| "Ego Node".to_string());
                    let endpoint = crate::p2p::get_public_endpoint().await;
                    // Pull city/country from the coverage status if available.
                    let (city, country) = {
                        let state  = handle_startup.state::<crate::app::AppState>();
                        let cache  = state.cache.lock().unwrap();
                        let loc    = cache.coverage_status.as_ref()
                            .and_then(|s| s.location.as_ref());
                        (loc.and_then(|l| l.city.clone()),
                         loc.and_then(|l| l.country.clone()))
                    };
                    if !ledger.address.is_empty() && !endpoint.is_empty() {
                        crate::p2p::register_with_relay(
                            ledger.address, name, endpoint, city, country,
                        ).await;
                    }

                    crate::p2p::fetch_peers_from_relay(&handle_startup).await;
                    crate::p2p::broadcast_peer_announce(&handle_startup).await;
                    crate::p2p::fetch_chain_from_relay(&handle_startup).await;
                    crate::p2p::sync_chain_from_peers().await;
                    // Retry any pending contact requests — automatically delivers
                    // once the remote comes online or updates their build.
                    crate::commands::messenger::retry_pending_contacts(&handle_startup).await;
                    // Poll relay inbox so messages/contact-requests arrive live
                    // without requiring an app restart.
                    crate::commands::messenger::fetch_relay_inbox(&handle_startup).await;
                }
            });

            // ── Task 3: background coverage loop ──────────────────────────
            // Runs every 60 s regardless of window visibility.
            // Handles: peer probing, PoC event recording, coverage status.
            // Keeps working when app is minimized or in system tray.
            let handle_coverage = app.handle();
            tauri::async_runtime::spawn(async move {
                crate::commands::coverage::run_background_coverage_loop(handle_coverage).await;
            });

            #[cfg(debug_assertions)]
            app.get_window("main").unwrap().open_devtools();

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}