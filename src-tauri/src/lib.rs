mod auth;
mod backup;
mod checksum_files;
mod command_catalog;
mod commands;
mod core_operations;
mod credentials;
mod database;
mod engine;
mod error;
mod error_log;
mod health;
mod maintenance;
mod models;
mod parsers;
mod scan_jobs;
mod security_policy;
mod ssh;
mod state;
mod terminal;
mod terminal_auth;
mod validation;
mod vulnerability_jobs;
mod vulnerability_matcher;
mod wordfence;
mod wordpress_users;
mod wp_cli;
mod wp_cli_catalog;

use database::Database;
use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
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
                vulnerability_cache_directory: data_dir.join("vulnerability-cache"),
                scan_concurrency: std::sync::atomic::AtomicUsize::new(scan_concurrency),
                auth: auth::AuthManager::default(),
                terminals: terminal::TerminalManager::default(),
                terminal_access: terminal_auth::TerminalAccessManager::default(),
                scan_jobs: scan_jobs::ScanJobManager::new(scan_concurrency),
                vulnerability_jobs: vulnerability_jobs::VulnerabilityRefreshManager::default(),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_auth_status,
            commands::setup_password,
            commands::login,
            commands::touch_session,
            commands::lock_app,
            commands::change_password,
            commands::set_idle_timeout,
            commands::list_audit_events,
            commands::list_error_logs,
            commands::get_wp_cli_catalog,
            commands::inspect_wp_cli_command,
            commands::execute_wp_cli_command,
            commands::begin_terminal_reauthentication,
            commands::cancel_terminal_reauthentication,
            commands::open_terminal,
            commands::write_terminal,
            commands::resize_terminal,
            commands::close_terminal,
            commands::list_sites,
            commands::save_site,
            commands::delete_site,
            commands::accept_host_key,
            commands::test_connection,
            commands::start_site_scan,
            commands::get_scan_job,
            commands::get_site_scan_job,
            commands::list_scan_jobs,
            commands::cancel_site_scan,
            commands::start_all_site_scans,
            commands::cancel_scan_jobs,
            commands::list_scan_runs,
            commands::list_finding_exceptions,
            commands::ignore_finding,
            commands::remove_finding_exception,
            commands::list_trusted_files,
            commands::trust_finding_file,
            commands::retrust_file,
            commands::revoke_trusted_file,
            commands::preview_checksum_finding,
            commands::delete_checksum_finding,
            commands::delete_checksum_findings,
            commands::get_settings,
            commands::save_settings,
            commands::get_wordfence_status,
            commands::save_wordfence_api_key,
            commands::remove_wordfence_api_key,
            commands::test_wordfence_connection,
            commands::start_wordfence_feed_refresh,
            commands::get_wordfence_feed_refresh_job,
            commands::match_cached_component_vulnerabilities,
            commands::open_vulnerability_reference,
            commands::check_updates,
            commands::list_cached_updates,
            commands::list_wordpress_users,
            commands::update_wordpress_user,
            commands::delete_wordpress_user,
            commands::run_update,
            commands::inspect_core_operation,
            commands::repair_wordpress_core,
            commands::update_wordpress_core,
            commands::run_maintenance,
            commands::list_maintenance_runs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
