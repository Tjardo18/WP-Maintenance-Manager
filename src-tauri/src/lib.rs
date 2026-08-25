mod backup;
mod command_catalog;
mod commands;
mod credentials;
mod database;
mod engine;
mod error;
mod health;
mod maintenance;
mod models;
mod parsers;
mod ssh;
mod state;
mod validation;

use database::Database;
use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let database = Database::initialize(data_dir.join("wp-maintenance-manager.sqlite3"))
                .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
            let scan_concurrency = database
                .scan_concurrency()
                .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?;
            app.manage(AppState {
                database,
                credentials: credentials::CredentialVault,
                ssh: std::sync::Arc::new(ssh::Ssh2Executor),
                backup_directory: data_dir.join("backups"),
                scan_concurrency: std::sync::atomic::AtomicUsize::new(scan_concurrency),
                bulk_scan_cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_sites,
            commands::save_site,
            commands::delete_site,
            commands::accept_host_key,
            commands::test_connection,
            commands::scan_site,
            commands::scan_all_sites,
            commands::cancel_bulk_scan,
            commands::get_settings,
            commands::save_settings,
            commands::check_updates,
            commands::run_update,
            commands::run_maintenance,
            commands::list_maintenance_runs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
