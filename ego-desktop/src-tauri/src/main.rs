#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod bft_committee;
mod bls_agg;
mod blocks;
mod ecvrf;
mod chain_db;
mod commands;
mod config;
mod email;
mod error;
mod l2;
mod ledger;
mod mempool;
mod p2p;
mod poc;
mod proof;
mod python_host;
mod rpc;
mod sharding;
mod tokenomics;
mod tls;
mod utils;

#[cfg(test)]
mod tests;

use tauri::{Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem};
use tauri::{CustomMenuItem, Menu, MenuItem, Submenu};

#[cfg(target_os = "windows")]
fn register_windows_notifications() {
    use std::os::windows::process::CommandExt;
    let aumid = "com.ego.desktop";
    let key = format!(r"HKCU\SOFTWARE\Classes\AppUserModelId\{}", aumid);

    // WinRT toast notifications require a PNG for IconUri — .ico silently fails to render.
    // Try next to the exe first (production), fall back to src-tauri/icons/ (dev build).
    let icon_path = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(|d| d.join("icons").join("icon.png")))
        .filter(|p| p.exists())
        .or_else(|| {
            let dev = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("icons")
                .join("icon.png");
            if dev.exists() { Some(dev) } else { None }
        })
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Register the AUMID so Windows trusts this process for toast notifications.
    // Must happen before Tauri's notification subsystem initialises.
    let _ = std::process::Command::new("reg")
        .args(["add", &key, "/v", "DisplayName", "/t", "REG_EXPAND_SZ", "/d", "Ego Desktop", "/f"])
        .creation_flags(0x08000000)
        .output();

    if !icon_path.is_empty() {
        let _ = std::process::Command::new("reg")
            .args(["add", &key, "/v", "IconUri", "/t", "REG_EXPAND_SZ", "/d", &icon_path, "/f"])
            .creation_flags(0x08000000)
            .output();
    }

    // Create a Start Menu shortcut the first time the app runs on this machine.
    // Windows 10/11 requires either an installed shortcut or the registry key above;
    // having both guarantees notifications work without admin rights on any machine.
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    if let Ok(appdata) = std::env::var("APPDATA") {
        let lnk = format!(r"{}\Microsoft\Windows\Start Menu\Programs\Ego Desktop.lnk", appdata);
        if !exe_path.is_empty() && !std::path::Path::new(&lnk).exists() {
            let script = format!(
                "$ws=New-Object -ComObject WScript.Shell;\
                 $s=$ws.CreateShortcut('{lnk}');\
                 $s.TargetPath='{exe}';\
                 $s.Description='Ego Desktop';\
                 $s.Save()",
                lnk = lnk.replace('\'', "''"),
                exe = exe_path.replace('\'', "''"),
            );
            let _ = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
                .creation_flags(0x08000000)
                .output();
        }
    }
}

static INSTANCE_LOCK: once_cell::sync::OnceCell<std::net::TcpListener> =
    once_cell::sync::OnceCell::new();

fn acquire_single_instance_lock() -> bool {
    let port: u16 = std::env::var("EGO_LOCK_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(47391);
    match std::net::TcpListener::bind(format!("127.0.0.1:{}", port)) {
        Ok(l) => {
            let _ = INSTANCE_LOCK.set(l);
            true
        }
        Err(_) => {
            // Another instance is running — poke it to show its window, then exit.
            let _ = std::net::TcpStream::connect(format!("127.0.0.1:{}", port));
            false
        }
    }
}

fn headless_main() {
    tracing::info!("Ego full node — P2P + BFT + RPC + Mempool");
    tracing::info!("Starting in headless full-node mode (EGO_HEADLESS=1)");
    tracing::info!("All GUI components disabled — blockchain services only");

    crate::app::init_global_app_state(std::sync::Arc::new(crate::app::AppState::new()));
    crate::p2p::prime_ed25519_seed_cache();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        crate::ledger::reconcile_stake_state();
        crate::chain_db::restore_in_memory_state_from_db();
        crate::sharding::load_agreed_shard_count_from_db();

        tokio::spawn(async {
            crate::p2p::start_p2p_server(None).await;
        });

        tokio::spawn(async {
            crate::mempool::run_batch_loop().await;
        });

        tokio::spawn(async {
            crate::rpc::start_rpc_server().await;
        });

        tokio::spawn(async {
            let _ = crate::tls::ensure_tls_certs();
            crate::rpc::start_https_server().await;
        });

        tokio::spawn(async {
            crate::commands::consensus::run_post_loop().await;
        });

        tokio::spawn(async {
            crate::p2p::run_shard_rebalance_monitor().await;
        });

        let rpc_port: u16 = std::env::var("EGO_RPC_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(47395);
        tracing::info!("All services started. RPC on port {}. P2P on port {}", rpc_port, crate::p2p::p2p_port());
        tracing::info!("Chain data: {:?}", crate::ledger::base_data_dir());
        tracing::info!("Press Ctrl+C to stop.");

        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutting down");
    });
}

fn main() {
    {
        use tracing_subscriber::{fmt, EnvFilter, prelude::*};
        let filter = EnvFilter::try_from_env("EGO_LOG")
            .unwrap_or_else(|_| EnvFilter::new("ego_desktop=info,warn"));
        tracing_subscriber::registry()
            .with(fmt::layer().with_target(false))
            .with(filter)
            .init();
    }
    tracing::info!("Ego Desktop starting");

    if std::env::var("EGO_HEADLESS").as_deref() == Ok("1") {
        headless_main();
        return;
    }

    #[cfg(all(target_os = "windows", not(debug_assertions)))]
    {
        extern "system" {
            fn SetStdHandle(nStdHandle: u32, hHandle: isize) -> i32;
        }
        const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;
        let log_path = crate::ledger::base_data_dir().join("ego.log");
        let _ = std::fs::create_dir_all(log_path.parent().unwrap_or(std::path::Path::new(".")));
        if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            use std::os::windows::io::IntoRawHandle;
            let handle = file.into_raw_handle() as isize;
            unsafe { SetStdHandle(STD_ERROR_HANDLE, handle); }
        }
    }

    #[cfg(target_os = "windows")]
    register_windows_notifications();

    #[cfg(target_os = "windows")]
    {
        extern "system" {
            fn SetThreadExecutionState(esFlags: u32) -> u32;
        }
        const ES_CONTINUOUS: u32          = 0x80000000;
        const ES_SYSTEM_REQUIRED: u32     = 0x00000001;
        const ES_AWAYMODE_REQUIRED: u32   = 0x00000040;
        unsafe {
            SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
        }
        eprintln!("[Node] Sleep prevention active (Windows)");
    }

    #[cfg(target_os = "macos")]
    {
        let pid = std::process::id().to_string();
        match std::process::Command::new("caffeinate")
            .args(["-di", "-w", &pid])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_child) => {
                std::mem::forget(_child);
                eprintln!("[Node] Sleep prevention active (macOS caffeinate)");
            }
            Err(e) => eprintln!("[Node] Sleep prevention unavailable: {e}"),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let result = std::process::Command::new("systemd-inhibit")
            .args([
                "--what=sleep:idle:handle-lid-switch",
                "--who=Ego Desktop",
                "--why=Node is sharing compute or storage",
                "--mode=block",
                "sleep", "infinity",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        match result {
            Ok(_child) => {
                std::mem::forget(_child);
                eprintln!("[Node] Sleep prevention active (Linux systemd-inhibit)");
            }
            Err(_) => {
                let _ = std::process::Command::new("xdg-screensaver")
                    .args(["reset"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                eprintln!("[Node] Sleep prevention: systemd-inhibit not available, using xdg-screensaver fallback");
            }
        }
    }

    if !acquire_single_instance_lock() {
        std::process::exit(0);
    }

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

    let shared_app_state = std::sync::Arc::new(app::AppState::new());
    crate::app::init_global_app_state(shared_app_state.clone());

    tauri::Builder::default()
        .manage((*shared_app_state).clone())
        .system_tray(tray)
        .menu(menu)

        .on_window_event(|event| {
            match event.event() {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    event.window().hide().unwrap();
                    api.prevent_close();
                }
                tauri::WindowEvent::Focused(true) => {
                    use tauri::Manager;
                    let win = event.window();
                    let app_handle = win.app_handle();
                    let state = app_handle.state::<app::AppState>();
                    let maybe_addr = state.pending_chat_address.lock().unwrap().take();
                    if let Some(addr) = maybe_addr {
                        // Ensure window is visible (may have been hidden to tray)
                        if !win.is_visible().unwrap_or(true) {
                            let _ = win.show();
                        }
                        let _ = win.emit("ego://open-chat", serde_json::json!({ "address": addr }));
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
                "quit" => {
                    crate::python_host::stop_all();
                    #[cfg(target_os = "windows")]
                    unsafe {
                        extern "system" { fn SetThreadExecutionState(esFlags: u32) -> u32; }
                        SetThreadExecutionState(0x80000000u32); // ES_CONTINUOUS only = release lock
                    }
                    std::process::exit(0);
                }
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
            commands::auth::import_wallet,
            commands::auth::switch_wallet,
            commands::auth::delete_wallet,
            commands::auth::rename_wallet,
            commands::auth::set_security_pin,
            commands::auth::verify_pin,
            commands::auth::pin_cache_status,
            commands::auth::reset_pin_with_recovery_phrase,
            commands::auth::get_password_status,
            commands::auth::set_password,
            commands::auth::verify_password,
            commands::auth::password_cache_status,
            commands::auth::reset_password_with_recovery_phrase,
            commands::auth::get_recovery_info,
            commands::auth::get_pin_status,
            commands::auth::verify_biometric,
            commands::wallet::get_balance,
            commands::wallet::send_transaction,
            commands::wallet::send_transaction_with_pin,
            commands::wallet::send_transaction_with_password,
            commands::wallet::prepare_transaction,
            commands::wallet::commit_transaction,
            commands::wallet::get_transaction_history,
            commands::wallet::get_tx_fee,
            commands::wallet::clear_pending_transactions,
            commands::storage::store_file,
            commands::storage::get_file_metadata,
            commands::storage::get_stored_files,
            commands::storage::get_egosafe_files,
            commands::storage::get_storage_metrics,
            commands::storage::configure_storage,
            commands::storage::get_available_drives,
            commands::storage::reset_storage,
            commands::storage::create_public_share,
            commands::storage::create_secure_share,
            commands::storage::import_secure_share,
            commands::storage::delete_stored_file,
            commands::storage::retrieve_file_preview,
            commands::storage::save_file_to_disk,
            commands::storage::download_stored_file,
            commands::storage::request_file_from_contact,
            commands::coverage::get_coverage_status,
            commands::coverage::get_poc_events,
            commands::coverage::get_network_peers,
            commands::earnings::get_earnings_data,
            commands::earnings::submit_poc_event,
            commands::earnings::get_poc_score,
            commands::staking::get_staking_info,
            commands::staking::stake_coins,
            commands::staking::unstake_coins,
            commands::staking::get_consensus_health,
            commands::auth::pq_cache_ready,
            commands::auth::get_app_settings,
            commands::auth::save_app_settings,
            commands::explorer::get_network_stats,
            commands::explorer::get_state_stats,
            commands::explorer::get_egoc_price_usd,
            commands::explorer::get_network_capacity,
            commands::explorer::get_p2p_status,
            commands::explorer::get_blocks,
            commands::explorer::get_all_transactions,
            commands::explorer::get_block_info,
            commands::explorer::get_transaction_info,
            commands::explorer::get_file_events,
            commands::explorer::get_base_fee,
            commands::explorer::get_supply_info,
            commands::explorer::set_log_level,
            commands::notifications::import_shared_file,
            commands::messenger::get_my_contact_bundle,
            commands::messenger::revoke_contact_bundle,
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
            commands::rollup::get_shard_map_status,
            commands::wallet::query_remote_node,
            commands::wallet::fetch_swap_rates,
            commands::wallet::changenow_estimate,
            commands::wallet::changenow_create_exchange,
            commands::wallet::changenow_get_status,
            commands::wallet::presale_create_iou,
            commands::wallet::presale_verify_iou,
            commands::wallet::presale_list_iou,
            commands::wallet::presale_info,
            commands::wallet::presale_stripe_checkout,
            commands::wallet::presale_stripe_verify,
            commands::wallet::presale_stripe_create_iou,
            commands::multichain::get_external_addresses,
            commands::multichain::fetch_chain_balance,
            commands::multichain::fetch_chain_transactions,
            commands::multichain::lookup_token_info,
            commands::multichain::add_custom_token,
            commands::multichain::get_custom_tokens,
            commands::multichain::remove_custom_token,
            commands::multichain::send_external_tx,
            commands::multichain::estimate_external_fee,
            commands::multichain::fetch_coin_chart,
            commands::multichain::fetch_single_price,
            commands::multichain::fetch_coin_candles,
            commands::multichain::request_ext_tx_code,
            commands::multichain::confirm_ext_tx,
            commands::ai::ask_ego_ai,
            commands::ai::save_ai_key,
            commands::ai::get_ai_key_status,
            commands::auth::get_mainnet_address,
            commands::light_client::get_block_headers,
            commands::light_client::get_tx_proof,
            commands::light_client::verify_tx_proof,
            commands::light_client::request_headers_from_peer,
            commands::light_client::get_account_proof,
            commands::governance::submit_governance_vote,
            commands::governance::get_governance_proposals,
            commands::governance::is_feature_active,
            commands::governance::create_dao_proposal,
            commands::governance::get_dao_proposals,
            commands::governance::get_dao_proposal,
            commands::governance::cast_stake_vote,
            commands::governance::grade_knowledge_test,
            commands::governance::cast_knowledge_vote,
            commands::governance::get_proposal_results,
            commands::governance::vote_ban_proposer,
            commands::governance::get_ban_status,
            commands::governance::get_proposal_rate_limit,
            commands::hosting::deploy_site,
            commands::hosting::deploy_site_begin,
            commands::hosting::deploy_site_file,
            commands::hosting::finalize_deploy,
            commands::hosting::get_hosted_sites,
            commands::hosting::undeploy_site,
            commands::hosting::set_custom_domain,
            commands::hosting::hosting_heartbeat,
            commands::hosting::get_hosting_nodes,
            commands::hosting::check_domain_available,
            commands::hosting::check_domain_status,
            commands::hosting::get_hosting_plans,
            commands::hosting::get_my_hosting_plan,
            commands::hosting::purchase_hosting_plan,
            commands::hosting::cancel_hosting_plan,
            commands::hosting::get_hosting_access,
            commands::hosting::setup_eo_certificates,
            commands::hosting::open_in_browser,
            commands::hosting::approve_python_site,
            commands::hosting::revoke_python_trust,
            commands::auth::export_wallet_backup,
            commands::auth::import_wallet_backup,
            commands::compute::detect_hardware,
            commands::compute::configure_compute_node,
            commands::compute::get_compute_status,
            commands::compute::get_compute_nodes,
            commands::compute::post_compute_job,
            commands::compute::cancel_compute_job,
            commands::compute::get_compute_jobs,
            commands::compute::accept_compute_job,
            commands::compute::complete_compute_job,
            commands::compute::get_compute_earnings,
            commands::compute::post_capacity_offer,
            commands::compute::cancel_capacity_offer,
            commands::compute::get_capacity_offers,
            commands::compute::book_reservation,
            commands::compute::send_reservation_heartbeat,
            commands::compute::get_reservations,
            commands::compute::terminate_reservation,
            commands::storage_deals::create_storage_deal,
            commands::storage_deals::send_storage_proof,
            commands::storage_deals::get_storage_deals,
            commands::storage_deals::terminate_storage_deal,
            commands::cluster::create_cluster_booking,
            commands::cluster::get_cluster_bookings,
            commands::cluster::terminate_cluster,
            commands::cluster::get_cluster_wg_config,
            commands::cluster::get_node_wg_config,
            commands::cluster::get_cluster_connect_info,
            commands::cluster::send_cluster_node_heartbeat,
            commands::l2::open_state_channel,
            commands::l2::get_my_channels,
            commands::l2::close_state_channel,
            commands::l2::finalize_state_channel,
            commands::l2::submit_l2_batch,
            commands::l2::get_rollup_batches,
            commands::l2::challenge_rollup_batch
        ])
        .setup(|app| {
            eprintln!("[Startup] setup() called — spawning background init threads");

            std::thread::spawn(|| {
                eprintln!("[Startup] RocksDB pre-warm thread started");
                let _ = crate::chain_db::get_db();
                eprintln!("[Startup] RocksDB pre-warm thread done");
            });

            std::thread::spawn(|| {
                eprintln!("[Startup] Seed+PQ cache thread started");
                crate::p2p::prime_ed25519_seed_cache();
                eprintln!("[Startup] Seed cache primed");
                crate::commands::auth::ensure_pq_cache();
                eprintln!("[Startup] PQ cache ready");
            });

            let window = app.get_window("main").unwrap();

            // Set window icon explicitly so the taskbar always shows the
            // correct high-res icon regardless of embedded EXE resources.
            let _ = window.set_icon(tauri::Icon::Raw(
                include_bytes!("../icons/icon.png").to_vec(),
            ));

            // Ask Windows 11 DWM to apply OS-level rounded corners.
            // DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2
            // Safe no-op on Windows 10 (attribute is silently ignored).
            #[cfg(target_os = "windows")]
            if let Ok(hwnd_ptr) = window.hwnd() {
                use winapi::shared::minwindef::DWORD;
                use winapi::shared::windef::HWND;
                use winapi::um::dwmapi::DwmSetWindowAttribute;
                // hwnd_ptr.0 is isize; cast through usize to get a *mut HWND__
                let hwnd = hwnd_ptr.0 as usize as HWND;
                let preference: DWORD = 2; // DWMWCP_ROUND
                unsafe {
                    DwmSetWindowAttribute(
                        hwnd,
                        33, // DWMWA_WINDOW_CORNER_PREFERENCE
                        &preference as *const DWORD as *const winapi::ctypes::c_void,
                        std::mem::size_of::<DWORD>() as DWORD,
                    );
                }
            }

            app.listen_global("frontend-ready", move |_| {
                window.show().unwrap();
                window.set_focus().unwrap();
            });

            // When another launch connects to our lock port, bring the window to front.
            {
                let win = app.get_window("main").unwrap();
                std::thread::spawn(move || {
                    if let Some(listener) = INSTANCE_LOCK.get() {
                        loop {
                            if listener.accept().is_ok() {
                                let _ = win.show();
                                let _ = win.unminimize();
                                let _ = win.set_focus();
                            }
                        }
                    }
                });
            }

            crate::poc::init_session_start();

            let handle_p2p = app.handle();
            tauri::async_runtime::spawn(async move {
                crate::p2p::start_p2p_server(Some(handle_p2p)).await;
            });

            let handle_startup = app.handle();
            tauri::async_runtime::spawn(async move {
                let my_endpoint = crate::p2p::wait_for_public_endpoint(60).await;

                if my_endpoint.contains("/p2p-circuit") {
                    tracing::info!("Relay circuit confirmed: {}", my_endpoint);
                } else if !my_endpoint.is_empty() {
                    tracing::warn!("Relay not confirmed in 20s — using: {}", my_endpoint);
                } else {
                    tracing::warn!("No endpoint — check network");
                }

                tokio::task::spawn_blocking(|| {
                    crate::chain_db::restore_in_memory_state_from_db();
                    crate::sharding::load_agreed_shard_count_from_db();

                    let my_addr = crate::ledger::Ledger::load().address;
                    if !my_addr.is_empty() {
                        crate::p2p::set_local_validator(&my_addr);
                        tracing::info!("Registered local validator: {}", &my_addr[..my_addr.len().min(20)]);
                    }
                }).await.ok();

                crate::p2p::fetch_and_cache_egoc_price().await;

                let no_oracle = std::env::var("EGO_NO_ORACLE").is_ok();

                // Bootstrap from oracle only while the P2P network is small
                let startup_peers = crate::p2p::get_known_peers().len();
                if !no_oracle && startup_peers < 50 {
                    crate::p2p::fetch_chain_from_oracle(Some(&handle_startup)).await;
                    crate::p2p::oracle_sync_chain().await;
                    tracing::info!("Oracle chain sync complete ({} peers, oracle active)", startup_peers);
                } else if no_oracle {
                    tracing::info!("Oracle disabled via EGO_NO_ORACLE — using pure P2P");
                } else {
                    tracing::info!("{} peers — skipping oracle, using P2P only", startup_peers);
                }

                crate::p2p::broadcast_peer_announce(Some(&handle_startup)).await;
                tracing::info!("Peer announce sent (endpoint: {})", my_endpoint);

                crate::p2p::restore_dht_cache().await;

                crate::p2p::dht_publish_self(&{
                    let l = crate::ledger::Ledger::load(); l.address
                }, &my_endpoint, "Ego Node").await;
                crate::p2p::dht_discover_peers().await;

                crate::p2p::dht_discover_relays().await;

                let peers = crate::p2p::get_known_peers();
                let ledger_addr = { let l = crate::ledger::Ledger::load(); l.address };
                crate::sharding::run_shard_startup(&ledger_addr, &my_endpoint, &peers, 0).await;
                crate::p2p::broadcast_shard_announce().await;
                tracing::info!("Shard announce sent");

                crate::p2p::dht_publish_shard_assignments(&ledger_addr, &my_endpoint).await;

                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                crate::p2p::sync_chain_from_peers().await;
                tracing::info!("Chain sync requested");

                crate::p2p::register_with_relay_as_ego_node().await;

                // PoSt check runs every 6 h — track iteration count (30s × 720 = 6h).
                let mut loop_tick: u32 = 0;
                const POST_EVERY_N_TICKS: u32 = 720;  // 720 × 30s = 6 h
                // Once the network has enough independent nodes the RPC oracle
                // is no longer needed — pure P2P gossip takes over.
                const P2P_SELF_SUFFICIENT_PEERS: usize = 50;

                let mut last_tick_wall = std::time::SystemTime::now();

                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    loop_tick = loop_tick.wrapping_add(1);

                    let now_wall = std::time::SystemTime::now();
                    let wall_elapsed = now_wall.duration_since(last_tick_wall).unwrap_or_default().as_secs();
                    last_tick_wall = now_wall;
                    if wall_elapsed > 60 {
                        tracing::info!("Wake-from-sleep detected ({}s gap) — reconnecting P2P", wall_elapsed);
                        crate::p2p::restore_dht_cache().await;
                        crate::p2p::dht_discover_peers().await;
                        crate::p2p::register_with_relay_as_ego_node().await;
                        crate::p2p::touch_proposal_timestamp();
                    }

                    let peer_count = crate::p2p::get_known_peers().len();
                    let use_oracle = !no_oracle && peer_count < P2P_SELF_SUFFICIENT_PEERS;

                    if use_oracle {
                        crate::p2p::fetch_chain_from_oracle(Some(&handle_startup)).await;
                    }
                    crate::p2p::broadcast_peer_announce(Some(&handle_startup)).await;
                    crate::p2p::sync_chain_from_peers().await;
                    crate::p2p::dht_discover_relays().await;

                    let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
                        .await.unwrap_or_default();
                    if !my_addr.is_empty() {
                        crate::commands::messenger::poll_relay_inbox(&my_addr, Some(&handle_startup)).await;
                    }

                    crate::p2p::fetch_and_cache_egoc_price().await;

                    crate::commands::outbox::flush_pending().await;

                    crate::p2p::check_file_replication().await;

                    if loop_tick % POST_EVERY_N_TICKS == 1 {
                        crate::proof::run_post_checks(Some(&handle_startup)).await;
                    }

                    let shard_peers = crate::p2p::get_known_peers();
                    let ledger_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
                        .await.unwrap_or_default();
                    let endpoint = crate::p2p::get_public_endpoint().await;
                    crate::sharding::run_shard_startup(&ledger_addr, &endpoint, &shard_peers, 0).await;
                    crate::p2p::broadcast_shard_announce().await;
                    crate::sharding::check_master_health(&ledger_addr, &endpoint, 0).await;

                    crate::p2p::push_shard_data_to_slaves().await;

                    let ep3 = crate::p2p::get_public_endpoint().await;
                    crate::p2p::dht_publish_shard_assignments(&ledger_addr, &ep3).await;
                    crate::p2p::broadcast_vacancy_notices().await;
                    crate::sharding::prune_observer_shards(&ledger_addr);
                }
            });

            tauri::async_runtime::spawn(async move {
                crate::commands::consensus::run_post_loop().await;
            });

            tauri::async_runtime::spawn(async move {
                crate::p2p::run_shard_rebalance_monitor().await;
            });

            // Restore any txs that were pending when the app last closed.
            crate::commands::tx_pending::restore_to_mempool();

            tauri::async_runtime::spawn(async move {
                crate::mempool::run_batch_loop().await;
            });

            let handle_coverage = app.handle();
            tauri::async_runtime::spawn(async move {
                crate::commands::coverage::run_background_coverage_loop(handle_coverage).await;
            });

            tauri::async_runtime::spawn(async move {
                crate::rpc::start_rpc_server().await;
            });

            tauri::async_runtime::spawn(async move {
                let _ = crate::tls::ensure_tls_certs();
                crate::rpc::start_https_server().await;
            });

            tauri::async_runtime::spawn(async move {
                crate::p2p::run_view_change_monitor().await;
            });

            tauri::async_runtime::spawn(async move {
                crate::p2p::run_porep_challenge_loop().await;
            });

            #[cfg(debug_assertions)]
            app.get_window("main").unwrap().open_devtools();

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
