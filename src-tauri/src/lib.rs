mod command_catalog;
mod commands;
mod credentials;
mod database;
mod engine;
mod error;
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
            app.manage(AppState {
                database,
                credentials: credentials::CredentialVault,
                ssh: std::sync::Arc::new(ssh::Ssh2Executor),
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
            commands::check_updates,
            commands::run_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
