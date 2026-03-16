// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod commands;
mod config;
mod crypto;
mod database;
mod error;
mod ledger;
mod mempool;
mod models;
mod p2p;
mod proof;
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
            commands::auth::verify_biometric,
            commands::wallet::get_balance,
            commands::wallet::send_transaction,
            commands::wallet::prepare_transaction,
            commands::wallet::commit_transaction,
            commands::wallet::get_transaction_history,
            commands::storage::store_file,
            commands::storage::get_file_metadata,
            commands::storage::get_stored_files,
            commands::storage::get_storage_metrics,
            commands::storage::configure_storage,
            commands::storage::delete_stored_file,
            commands::storage::retrieve_file_preview,
            commands::storage::save_file_to_disk,
            commands::storage::download_stored_file,
            commands::storage::request_file_from_contact,
            commands::files::encrypt_file,
            commands::files::decrypt_file,
            commands::coverage::get_coverage_status,
            commands::coverage::get_poc_events,
            commands::coverage::get_network_peers,
            commands::earnings::get_earnings_data,
            commands::earnings::submit_poc_event,
            commands::earnings::get_poc_score,
            commands::staking::get_staking_info,
            commands::staking::stake_coins,
            commands::auth::get_app_settings,
            commands::auth::save_app_settings,
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
            commands::messenger::rename_contact,
            commands::messenger::clear_messages,
            commands::messenger::delete_message,
            commands::storage::open_file,
            commands::consensus::get_porep_status,
            commands::consensus::respond_to_challenges,
            commands::consensus::get_post_score,
            commands::consensus::get_combined_drs,
            commands::consensus::get_tokenomics,
            commands::contracts::compile_urego,
            commands::contracts::deploy_contract,
            commands::contracts::call_contract,
            commands::contracts::get_contract_state,
            commands::contracts::list_deployed_contracts,
            commands::contracts::get_contract_events,
            commands::rollup::get_rollup_status,
            commands::rollup::get_shard_stats,
            commands::wallet::query_remote_node,
            commands::ai::ask_ego_ai,
            commands::ai::save_ai_key,
            commands::ai::get_ai_key_status
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

                crate::p2p::fetch_chain_from_oracle(&handle_startup).await;
                eprintln!("[Startup] Oracle chain sync complete");

                crate::p2p::broadcast_peer_announce(&handle_startup).await;
                eprintln!("[Startup] Peer announce sent (endpoint: {})", my_endpoint);

                // Publish to DHT so peers can find us without the central relay
                crate::p2p::dht_publish_self(&{
                    let l = crate::ledger::Ledger::load(); l.address
                }, &my_endpoint, "Ego Node").await;
                crate::p2p::dht_discover_peers().await;

                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                crate::p2p::sync_chain_from_peers().await;
                eprintln!("[Startup] Chain sync requested");

                // Keep-alive: Oracle sync + peer announce + direct P2P sync every 30 s.
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    crate::p2p::fetch_chain_from_oracle(&handle_startup).await;
                    crate::p2p::broadcast_peer_announce(&handle_startup).await;
                    crate::p2p::sync_chain_from_peers().await;
                }
            });

            // ── Task 3: PoST proof loop ────────────────────────────────────
            // Polls the relay for pending PoST challenges every 30 minutes and
            // automatically responds with Merkle proofs over stored files.
            tauri::async_runtime::spawn(async move {
                crate::commands::consensus::run_post_loop().await;
            });

            // ── Task 4: rollup batch loop ──────────────────────────────
            // Drains the shard-partitioned mempool every 50 ms and mines
            // one block per batch (up to 2,000 TXs × 16 shards = 32,000
            // TXs per tick → ~100,000 TPS target).
            tauri::async_runtime::spawn(async move {
                crate::mempool::run_batch_loop().await;
            });

            // ── Task 5: background coverage loop ──────────────────────────
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