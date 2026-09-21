use crate::{
    command_catalog::{MAX_SCAN_RESULTS, RemoteAction, RemoteCommand, build},
    database::utc_now,
    error::AppError,
    models::{
        ChecksumStatus, Finding, FindingSeverity, InstalledSoftware, ScanCheck, ScanResult,
        SiteStatus, StepStatus, StoredSite, UpdateItem, UpdateKind, WordPressUser,
    },
    parsers,
    snapshot_builder::{SnapshotBuildSection, SnapshotCronInput},
    snapshots::SnapshotCore,
    ssh::{ExecOutput, SshConnection, SshExecutor},
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ScanSnapshotSections {
    pub core: SnapshotBuildSection<SnapshotCore>,
    pub plugins: SnapshotBuildSection<Vec<InstalledSoftware>>,
    pub themes: SnapshotBuildSection<Vec<InstalledSoftware>>,
    pub users: SnapshotBuildSection<Vec<WordPressUser>>,
    pub configuration: SnapshotBuildSection<BTreeMap<String, serde_json::Value>>,
    pub cron: SnapshotBuildSection<Vec<SnapshotCronInput>>,
}

pub struct ScanOutcome {
    pub result: ScanResult,
    pub security_status: String,
    pub wordpress_version: String,
    pub php_version: String,
    pub wp_cli_version: Option<String>,
    pub updates: Option<Vec<UpdateItem>>,
    pub inventory: Vec<InstalledSoftware>,
    pub snapshot_sections: ScanSnapshotSections,
}

struct ScannedUpdates {
    updates: Vec<UpdateItem>,
    errors: Vec<AppError>,
    inventory: Vec<InstalledSoftware>,
    plugins: SnapshotBuildSection<Vec<InstalledSoftware>>,
    themes: SnapshotBuildSection<Vec<InstalledSoftware>>,
}

pub trait ScanProgress {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn step_started(&mut self, _key: &str) {}
    fn step_finished(
        &mut self,
        _key: &str,
        _status: StepStatus,
        _duration_ms: u64,
        _detail: Option<String>,
    ) {
    }
    fn step_failed_diagnostic(
        &mut self,
        _key: &str,
        _user_message: &str,
        _technical_details: Option<&str>,
        _duration_ms: u64,
    ) {
    }
}

struct NoopScanProgress;
impl ScanProgress for NoopScanProgress {}

pub fn scan_site_with_exclusions(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    modified_days: u16,
    excluded_root_directories: &[String],
) -> Result<ScanOutcome, AppError> {
    scan_site_with_progress_and_exclusions(
        executor,
        stored,
        credential,
        modified_days,
        excluded_root_directories,
        &mut NoopScanProgress,
    )
}

#[cfg(test)]
pub fn scan_site_with_progress(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    modified_days: u16,
    progress: &mut dyn ScanProgress,
) -> Result<ScanOutcome, AppError> {
    scan_site_with_progress_and_exclusions(
        executor,
        stored,
        credential,
        modified_days,
        &[],
        progress,
    )
}

pub fn scan_site_with_progress_and_exclusions(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    modified_days: u16,
    excluded_root_directories: &[String],
    progress: &mut dyn ScanProgress,
) -> Result<ScanOutcome, AppError> {
    let started_at = utc_now();
    let mut connection = measured_result(progress, "ssh_connect", || {
        executor.open_connection(&stored.site, credential)
    })?;
    measured_result(progress, "wordpress_detection", || {
        connection_text_action(connection.as_mut(), stored, RemoteAction::DetectWordPress)
            .map(|_| ())
    })?;
    let (wordpress_version, php_version) = measured_result(progress, "wordpress", || {
        Ok((
            connection_text_action(
                connection.as_mut(),
                stored,
                RemoteAction::GetWordPressVersion,
            )?
            .trim()
            .to_owned(),
            connection_text_action(connection.as_mut(), stored, RemoteAction::GetPhpVersion)?
                .trim()
                .to_owned(),
        ))
    })?;
    let wp_cli_version = measured_wp_cli_version(progress, || {
        connection_text_action(connection.as_mut(), stored, RemoteAction::GetWpCliVersion)
    })?;
    let mut truncated = false;
    let mut checks = Vec::new();

    checks.push(measured_check(progress, "checksum", || {
        checksum_check(connection.as_mut(), stored, excluded_root_directories)
    })?);
    let mut snapshot_users = SnapshotBuildSection::Failed;
    checks.push(measured_check(
        progress,
        "users",
        || match connection_text_action(connection.as_mut(), stored, RemoteAction::ListUsers) {
            Ok(output) => match measured_parse(&stored.site.id, "users", || {
                parsers::parse_wordpress_users(&output)
            }) {
                Ok(users) => {
                    let findings = parsers::user_findings(&users);
                    snapshot_users = SnapshotBuildSection::Complete(users);
                    findings_check("users", "Gebruikersaccounts", findings, "accounts", false)
                }
                Err(error) => failed_check("users", "Gebruikersaccounts", error),
            },
            Err(error) => failed_check("users", "Gebruikersaccounts", error),
        },
    )?);

    let mut php_cut = false;
    checks.push(measured_check(
        progress,
        "php",
        || match connection_binary_action(connection.as_mut(), stored, RemoteAction::FindPhpFiles) {
            Ok(output) => {
                let (findings, cut) = measured_parse(&stored.site.id, "php_inventory", || {
                    parsers::parse_php_inventory(&output, &stored.site.wordpress_path)
                });
                php_cut = cut;
                php_inventory_check(findings, cut)
            }
            Err(error) => failed_check("php_files", "PHP in wp-content", error),
        },
    )?);
    truncated |= php_cut;

    let mut uploads_cut = false;
    checks.push(measured_check(
        progress,
        "uploads",
        || match connection_binary_action(
            connection.as_mut(),
            stored,
            RemoteAction::FindPhpInUploads,
        ) {
            Ok(output) => {
                let (findings, cut) = measured_parse(&stored.site.id, "php_uploads", || {
                    parsers::parse_nul_paths(&output, &stored.site.wordpress_path, true)
                });
                uploads_cut = cut;
                findings_check(
                    "php_uploads",
                    "PHP in uploads",
                    findings,
                    "PHP-bestanden in uploads",
                    cut,
                )
            }
            Err(error) => failed_check("php_uploads", "PHP in uploads", error),
        },
    )?);
    truncated |= uploads_cut;

    let mut modified_cut = false;
    checks.push(measured_check(
        progress,
        "modified",
        || match connection_binary_action(
            connection.as_mut(),
            stored,
            RemoteAction::FindModifiedFiles {
                days: modified_days,
            },
        ) {
            Ok(output) => {
                let (findings, cut) = measured_parse(&stored.site.id, "modified_files", || {
                    parsers::parse_modified_files(&output, &stored.site.wordpress_path)
                });
                modified_cut = cut;
                findings_check(
                    "modified_files",
                    &format!("Gewijzigde bestanden afgelopen {modified_days} dagen"),
                    findings,
                    "gewijzigde bestanden",
                    cut,
                )
            }
            Err(error) => failed_check("modified_files", "Gewijzigde bestanden", error),
        },
    )?);
    truncated |= modified_cut;

    let mut permissions_cut = false;
    checks.push(measured_check(
        progress,
        "permissions",
        || match connection_binary_action(
            connection.as_mut(),
            stored,
            RemoteAction::CheckUnsafePermissions,
        ) {
            Ok(output) => {
                let (findings, cut) = measured_parse(&stored.site.id, "permissions", || {
                    parsers::permission_findings(&output, &stored.site.wordpress_path)
                });
                permissions_cut = cut;
                findings_check(
                    "permissions",
                    "Bestandsrechten",
                    findings,
                    "onveilige rechten",
                    cut,
                )
            }
            Err(error) => failed_check("permissions", "Bestandsrechten", error),
        },
    )?);
    truncated |= permissions_cut;

    let mut snapshot_configuration = SnapshotBuildSection::Failed;
    checks.push(measured_check(
        progress,
        "configuration",
        || match connection_text_action(
            connection.as_mut(),
            stored,
            RemoteAction::CheckSelectedWpConfigConstants,
        ) {
            Ok(output) => match measured_parse(&stored.site.id, "configuration", || {
                parsers::parse_selected_config(&output)
            }) {
                Ok(mut configuration) => {
                    configuration.insert("php_version".into(), php_version.clone().into());
                    let findings = parsers::config_findings(&configuration);
                    snapshot_configuration = SnapshotBuildSection::Complete(configuration);
                    findings_check(
                        "configuration",
                        "WordPress-configuratie",
                        findings,
                        "instellingen",
                        false,
                    )
                }
                Err(error) => failed_check("configuration", "WordPress-configuratie", error),
            },
            Err(error) => failed_check("configuration", "WordPress-configuratie", error),
        },
    )?);

    let mut snapshot_cron = SnapshotBuildSection::Failed;
    checks.push(measured_check(
        progress,
        "cron",
        || match connection_text_action(connection.as_mut(), stored, RemoteAction::ListCronEvents) {
            Ok(output) => match measured_parse(&stored.site.id, "cron", || {
                parsers::parse_snapshot_cron(&output)
            }) {
                Ok(events) => {
                    let count = events.len();
                    snapshot_cron = SnapshotBuildSection::Complete(events);
                    ScanCheck {
                        key: "cron".into(),
                        label: "WordPress-cron".into(),
                        status: StepStatus::Success,
                        summary: format!("{count} cronregels veilig geïnventariseerd."),
                        technical_details: None,
                        findings: Vec::new(),
                    }
                }
                Err(error) => failed_check("cron", "WordPress-cron", error),
            },
            Err(error) => failed_check("cron", "WordPress-cron", error),
        },
    )?);

    checks.push(measured_check(
        progress,
        "database",
        || match connection_text_action(connection.as_mut(), stored, RemoteAction::CheckDatabase) {
            Ok(_) => ScanCheck {
                key: "database".into(),
                label: "Database".into(),
                status: StepStatus::Success,
                summary: "Databasecontrole voltooid zonder gemelde fouten.".into(),
                technical_details: None,
                findings: Vec::new(),
            },
            Err(error) => failed_check("database", "Database", error),
        },
    )?);

    let ScannedUpdates {
        updates: detected_updates,
        errors: update_errors,
        mut inventory,
        plugins,
        themes,
    } = scan_updates_with_progress(connection.as_mut(), stored, &wordpress_version, progress)?;
    inventory.insert(
        0,
        InstalledSoftware {
            software_type: "core".into(),
            slug: "wordpress".into(),
            name: "WordPress".into(),
            version: wordpress_version.clone(),
            status: "active".into(),
            update_version: detected_updates
                .iter()
                .find(|update| update.kind == UpdateKind::Core)
                .map(|update| update.new_version.clone()),
            observed_at: utc_now(),
        },
    );
    let updates = update_errors.is_empty().then_some(detected_updates.clone());
    checks.push(if update_errors.is_empty() {
        ScanCheck {
            key: "updates".into(),
            label: "Updatecontrole".into(),
            status: StepStatus::Success,
            summary: format!("{} beschikbare updates gevonden.", detected_updates.len()),
            technical_details: None,
            findings: Vec::new(),
        }
    } else {
        ScanCheck {
            key: "updates".into(),
            label: "Updatecontrole".into(),
            status: StepStatus::Failed,
            summary: format!(
                "{} van de updatecontroles zijn mislukt.",
                update_errors.len()
            ),
            technical_details: Some(
                update_errors
                    .iter()
                    .filter_map(AppError::safe_diagnostic)
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            findings: Vec::new(),
        }
    });

    checks.push(measured_check(
        progress,
        "homepage",
        || match crate::health::check_homepage(&stored.site.url) {
            Ok(result) => ScanCheck {
                key: "homepage".into(),
                label: "Homepage".into(),
                status: if result.reachable {
                    StepStatus::Success
                } else {
                    StepStatus::Warning
                },
                summary: result.detail,
                technical_details: None,
                findings: Vec::new(),
            },
            Err(error) => failed_check("homepage", "Homepage", error),
        },
    )?);

    let security_status = security_summary(&checks).to_owned();
    let status = scan_status(&checks);
    let result = ScanResult {
        id: Uuid::new_v4().to_string(),
        site_id: stored.site.id.clone(),
        started_at,
        finished_at: utc_now(),
        status,
        checks,
        truncated,
    };
    Ok(ScanOutcome {
        result,
        security_status,
        wordpress_version: wordpress_version.clone(),
        php_version: php_version.clone(),
        wp_cli_version,
        updates,
        inventory,
        snapshot_sections: ScanSnapshotSections {
            core: SnapshotBuildSection::Complete(SnapshotCore {
                version: wordpress_version.clone(),
                locale: match &snapshot_configuration {
                    SnapshotBuildSection::Complete(configuration) => configuration
                        .get("locale")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                    SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => None,
                },
                multisite: match &snapshot_configuration {
                    SnapshotBuildSection::Complete(configuration) => configuration
                        .get("multisite")
                        .and_then(serde_json::Value::as_bool),
                    SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => None,
                },
                php_version: Some(php_version.clone()),
            }),
            plugins,
            themes,
            users: snapshot_users,
            configuration: snapshot_configuration,
            cron: snapshot_cron,
        },
    })
}

pub fn check_updates(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
) -> Result<Vec<UpdateItem>, AppError> {
    let mut connection = executor.open_connection(&stored.site, credential)?;
    let current = connection_text_action(
        connection.as_mut(),
        stored,
        RemoteAction::GetWordPressVersion,
    )?;
    check_updates_on_connection(connection.as_mut(), stored, current.trim())
}

fn check_updates_on_connection(
    connection: &mut dyn SshConnection,
    stored: &StoredSite,
    current_version: &str,
) -> Result<Vec<UpdateItem>, AppError> {
    let mut updates = parsers::parse_core_updates(
        &connection_text_action(connection, stored, RemoteAction::CheckCoreUpdates)?,
        current_version,
    )?;
    updates.extend(parsers::parse_update_list(
        &connection_text_action(connection, stored, RemoteAction::ListPluginUpdates)?,
        UpdateKind::Plugin,
    )?);
    updates.extend(parsers::parse_update_list(
        &connection_text_action(connection, stored, RemoteAction::ListThemeUpdates)?,
        UpdateKind::Theme,
    )?);
    Ok(updates)
}

fn scan_updates_with_progress(
    connection: &mut dyn SshConnection,
    stored: &StoredSite,
    current_version: &str,
    progress: &mut dyn ScanProgress,
) -> Result<ScannedUpdates, AppError> {
    let mut updates = Vec::new();
    let mut errors = Vec::new();
    let mut inventory = Vec::new();
    let mut plugin_inventory = SnapshotBuildSection::Failed;
    let mut theme_inventory = SnapshotBuildSection::Failed;
    let observed_at = utc_now();

    let core = measured_result(progress, "core_updates", || {
        let output = connection_text_action(connection, stored, RemoteAction::CheckCoreUpdates)?;
        measured_parse(&stored.site.id, "core_updates", || {
            parsers::parse_core_updates(&output, current_version)
        })
    });
    match core {
        Ok(items) => updates.extend(items),
        Err(error) if error.category == "scan_cancelled" => return Err(error),
        Err(error) => errors.push(error),
    }

    let plugins = measured_result(progress, "plugin_list", || {
        let output = connection_text_action(connection, stored, RemoteAction::ListPluginUpdates)?;
        let updates = measured_parse(&stored.site.id, "plugin_updates", || {
            parsers::parse_update_list(&output, UpdateKind::Plugin)
        })?;
        let installed = measured_parse(&stored.site.id, "plugin_inventory", || {
            parsers::parse_software_inventory(&output, UpdateKind::Plugin, &observed_at)
        })?;
        Ok((updates, installed))
    });
    match plugins {
        Ok((items, installed)) => {
            updates.extend(items);
            plugin_inventory = SnapshotBuildSection::Complete(installed.clone());
            inventory.extend(installed);
        }
        Err(error) if error.category == "scan_cancelled" => return Err(error),
        Err(error) => errors.push(error),
    }

    let themes = measured_result(progress, "theme_list", || {
        let output = connection_text_action(connection, stored, RemoteAction::ListThemeUpdates)?;
        let updates = measured_parse(&stored.site.id, "theme_updates", || {
            parsers::parse_update_list(&output, UpdateKind::Theme)
        })?;
        let installed = measured_parse(&stored.site.id, "theme_inventory", || {
            parsers::parse_software_inventory(&output, UpdateKind::Theme, &observed_at)
        })?;
        Ok((updates, installed))
    });
    match themes {
        Ok((items, installed)) => {
            updates.extend(items);
            theme_inventory = SnapshotBuildSection::Complete(installed.clone());
            inventory.extend(installed);
        }
        Err(error) if error.category == "scan_cancelled" => return Err(error),
        Err(error) => errors.push(error),
    }

    Ok(ScannedUpdates {
        updates,
        errors,
        inventory,
        plugins: plugin_inventory,
        themes: theme_inventory,
    })
}

fn cancelled_error() -> AppError {
    AppError::ssh(
        "scan_cancelled",
        "De scan is geannuleerd.",
        "annulering aangevraagd tussen scanstappen",
        false,
    )
}

fn measured_result<T>(
    progress: &mut dyn ScanProgress,
    key: &str,
    operation: impl FnOnce() -> Result<T, AppError>,
) -> Result<T, AppError> {
    if progress.is_cancelled() {
        return Err(cancelled_error());
    }
    progress.step_started(key);
    let started = Instant::now();
    let result = operation();
    let duration = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => progress.step_finished(key, StepStatus::Success, duration, None),
        Err(error) => {
            progress.step_failed_diagnostic(
                key,
                &error.user_message,
                error.safe_diagnostic().as_deref(),
                duration,
            );
            progress.step_finished(
                key,
                StepStatus::Failed,
                duration,
                Some(error.user_message.clone()),
            );
        }
    }
    result
}

fn measured_wp_cli_version(
    progress: &mut dyn ScanProgress,
    operation: impl FnOnce() -> Result<String, AppError>,
) -> Result<Option<String>, AppError> {
    if progress.is_cancelled() {
        return Err(cancelled_error());
    }
    progress.step_started("wp_cli_version");
    let started = Instant::now();
    let result = operation();
    let duration = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match result {
        Ok(output) => {
            let version = normalize_wp_cli_version(&output);
            let (status, detail) = version.as_ref().map_or_else(
                || {
                    (
                        StepStatus::Warning,
                        "WP-CLI-versie is niet beschikbaar.".to_owned(),
                    )
                },
                |version| (StepStatus::Success, version.clone()),
            );
            progress.step_finished("wp_cli_version", status, duration, Some(detail));
            Ok(version)
        }
        Err(error) => {
            progress.step_finished(
                "wp_cli_version",
                StepStatus::Warning,
                duration,
                Some("WP-CLI-versie kon niet worden opgehaald; de scan gaat door.".into()),
            );
            eprintln!(
                "wp_cli_version_probe_failed diagnostic={}",
                error
                    .safe_diagnostic()
                    .unwrap_or_else(|| error.category.clone())
            );
            Ok(None)
        }
    }
}

pub fn normalize_wp_cli_version(output: &str) -> Option<String> {
    let value = output.trim();
    if value.is_empty() {
        None
    } else if value.starts_with("WP-CLI ") {
        Some(value.to_owned())
    } else {
        Some(format!("WP-CLI {value}"))
    }
}

fn measured_check(
    progress: &mut dyn ScanProgress,
    key: &str,
    operation: impl FnOnce() -> ScanCheck,
) -> Result<ScanCheck, AppError> {
    if progress.is_cancelled() {
        return Err(cancelled_error());
    }
    progress.step_started(key);
    let started = Instant::now();
    let check = operation();
    let duration = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if check.status == StepStatus::Failed {
        progress.step_failed_diagnostic(
            key,
            &check.summary,
            check.technical_details.as_deref(),
            duration,
        );
    }
    progress.step_finished(key, check.status, duration, Some(check.summary.clone()));
    Ok(check)
}

fn measured_parse<T>(site_id: &str, parser: &str, operation: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let result = operation();
    eprintln!(
        "site_id={} parser={} parsing_ms={} status=complete",
        site_id,
        parser,
        started.elapsed().as_millis()
    );
    result
}

fn connection_text_action(
    connection: &mut dyn SshConnection,
    stored: &StoredSite,
    action: RemoteAction,
) -> Result<String, AppError> {
    connection_checked_output(connection, build(&stored.site.wordpress_path, action)?)?
        .stdout_text()
}

fn connection_binary_action(
    connection: &mut dyn SshConnection,
    stored: &StoredSite,
    action: RemoteAction,
) -> Result<Vec<u8>, AppError> {
    Ok(connection_checked_output(connection, build(&stored.site.wordpress_path, action)?)?.stdout)
}

fn connection_checked_output(
    connection: &mut dyn SshConnection,
    command: RemoteCommand,
) -> Result<ExecOutput, AppError> {
    let output = connection.execute(&command)?;
    if output.exit_code != 0 {
        return Err(AppError::command_failed(
            command.action_name,
            output.exit_code,
            &String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(output)
}

pub fn run_update(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    kind: &str,
    slug: Option<&str>,
) -> Result<(), AppError> {
    executor.authenticate(&stored.site, credential)?;
    let actions = match kind {
        "core" => vec![RemoteAction::UpdateCore],
        "plugin" => vec![RemoteAction::UpdatePlugin {
            slug: slug
                .ok_or_else(|| AppError::validation("Kies een plugin om bij te werken."))?
                .to_owned(),
        }],
        "theme" => vec![RemoteAction::UpdateTheme {
            slug: slug
                .ok_or_else(|| AppError::validation("Kies een thema om bij te werken."))?
                .to_owned(),
        }],
        "plugins" => vec![RemoteAction::UpdateAllPlugins],
        "themes" => vec![RemoteAction::UpdateAllThemes],
        "languages" => vec![RemoteAction::UpdateLanguages],
        "database" => vec![RemoteAction::UpdateDatabase],
        "all" => vec![
            RemoteAction::UpdateCore,
            RemoteAction::UpdateAllPlugins,
            RemoteAction::UpdateAllThemes,
            RemoteAction::UpdateLanguages,
            RemoteAction::UpdateDatabase,
        ],
        _ => {
            return Err(AppError::validation("Deze updateactie is niet toegestaan."));
        }
    };
    for action in actions {
        let command = build(&stored.site.wordpress_path, action)?;
        if !command.mutating {
            return Err(AppError::validation(
                "Een niet-muterende controle kan niet als update worden uitgevoerd.",
            ));
        }
        checked_output(executor, &stored.site, credential, command)?;
    }
    Ok(())
}

pub fn text_action(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    action: RemoteAction,
) -> Result<String, AppError> {
    checked_output(
        executor,
        &stored.site,
        credential,
        build(&stored.site.wordpress_path, action)?,
    )?
    .stdout_text()
}

pub fn checked_output(
    executor: &dyn SshExecutor,
    site: &crate::models::Site,
    credential: Option<&str>,
    command: RemoteCommand,
) -> Result<ExecOutput, AppError> {
    let output = executor.execute(site, credential, &command)?;
    if output.exit_code != 0 {
        return Err(AppError::command_failed(
            command.action_name,
            output.exit_code,
            &String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(output)
}

fn checksum_check(
    connection: &mut dyn SshConnection,
    stored: &StoredSite,
    excluded_root_directories: &[String],
) -> ScanCheck {
    let observed_at = utc_now();
    let command = match build(
        &stored.site.wordpress_path,
        RemoteAction::VerifyCoreChecksums,
    ) {
        Ok(command) => command,
        Err(error) => return failed_checksum_check(error, &observed_at),
    };
    match connection.execute(&command) {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parsed = measured_parse(&stored.site.id, "core_checksum", || {
                parsers::parse_checksum_output(&stdout, &observed_at)
            });
            match parsed {
                Ok(findings) if output.exit_code == 0 || !findings.is_empty() => {
                    checksum_with_root_files(
                        connection,
                        stored,
                        findings,
                        excluded_root_directories,
                        &observed_at,
                    )
                }
                Ok(_) if checksum_json_format_is_unsupported(&output) => checksum_plain_fallback(
                    connection,
                    stored,
                    &observed_at,
                    excluded_root_directories,
                ),
                Ok(_) => {
                    failed_checksum_check(checksum_command_error(&command, &output), &observed_at)
                }
                Err(_) if output.exit_code == 0 || checksum_json_format_is_unsupported(&output) => {
                    checksum_plain_fallback(
                        connection,
                        stored,
                        &observed_at,
                        excluded_root_directories,
                    )
                }
                Err(error) => failed_checksum_check(
                    checksum_parse_error(&command, &output, error),
                    &observed_at,
                ),
            }
        }
        Err(error) => failed_checksum_check(error, &observed_at),
    }
}

fn checksum_plain_fallback(
    connection: &mut dyn SshConnection,
    stored: &StoredSite,
    observed_at: &str,
    excluded_root_directories: &[String],
) -> ScanCheck {
    let command = match build(
        &stored.site.wordpress_path,
        RemoteAction::VerifyCoreChecksumsPlain,
    ) {
        Ok(command) => command,
        Err(error) => return failed_checksum_check(error, observed_at),
    };
    let output = match connection.execute(&command) {
        Ok(output) => output,
        Err(error) => return failed_checksum_check(error, observed_at),
    };
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    match measured_parse(&stored.site.id, "core_checksum_fallback", || {
        parsers::parse_checksum_plain_output(&combined, observed_at)
    }) {
        Ok(findings) if output.exit_code == 0 || !findings.is_empty() => checksum_with_root_files(
            connection,
            stored,
            findings,
            excluded_root_directories,
            observed_at,
        ),
        Ok(_) => failed_checksum_check(checksum_command_error(&command, &output), observed_at),
        Err(error) => failed_checksum_check(error, observed_at),
    }
}

#[derive(Deserialize)]
struct UnexpectedRootFilesOutput {
    files: Vec<String>,
    truncated: bool,
    scanned_entries: u64,
}

fn checksum_with_root_files(
    connection: &mut dyn SshConnection,
    stored: &StoredSite,
    mut findings: Vec<Finding>,
    excluded_root_directories: &[String],
    observed_at: &str,
) -> ScanCheck {
    match unexpected_root_file_findings(connection, stored, excluded_root_directories, observed_at)
    {
        Ok((root_findings, truncated, scanned_entries)) => {
            findings.extend(root_findings);
            if truncated {
                findings.push(checksum_scan_message(
                    "Aanvullende rootcontrole afgekapt",
                    format!(
                        "De aanvullende rootcontrole stopte na {scanned_entries} items door de tijd- of resultaatlimiet. Bevestigde child-installaties waren al uitgesloten."
                    ),
                    observed_at,
                ));
            }
            checksum_findings_check(exclude_child_installation_findings(
                findings,
                excluded_root_directories,
            ))
        }
        Err(error) => {
            let technical_details = error.safe_diagnostic();
            findings.push(checksum_scan_message(
                "Aanvullende rootcontrole niet voltooid",
                error.user_message,
                observed_at,
            ));
            let mut check = checksum_findings_check(findings);
            check.technical_details = technical_details;
            check
        }
    }
}

fn unexpected_root_file_findings(
    connection: &mut dyn SshConnection,
    stored: &StoredSite,
    excluded_root_directories: &[String],
    observed_at: &str,
) -> Result<(Vec<Finding>, bool, u64), AppError> {
    let command = build(
        &stored.site.wordpress_path,
        RemoteAction::FindUnexpectedRootFiles {
            excluded_directories: excluded_root_directories.to_vec(),
        },
    )?;
    let output = connection.execute(&command)?;
    if output.exit_code != 0 {
        return Err(checksum_command_error(&command, &output));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: UnexpectedRootFilesOutput =
        serde_json::from_str(stdout.trim()).map_err(|error| {
            AppError::ssh(
                "checksum_root_parse_failed",
                "De aanvullende WordPress-rootcontrole kon niet veilig worden gelezen.",
                format!("Actie: {}; JSON-fout: {error}", command.action_name),
                true,
            )
        })?;
    if result.files.len() > MAX_SCAN_RESULTS || result.scanned_entries > 20_001 {
        return Err(AppError::ssh(
            "checksum_root_limit_invalid",
            "De aanvullende WordPress-rootcontrole gaf een ongeldige hoeveelheid gegevens terug.",
            format!(
                "Actie: {}; bestanden: {}; bekeken items: {}",
                command.action_name,
                result.files.len(),
                result.scanned_entries
            ),
            false,
        ));
    }
    let mut unique_paths = BTreeSet::new();
    let mut findings = Vec::with_capacity(result.files.len());
    for path in result.files {
        if unique_paths.insert(path.clone()) {
            findings.push(parsers::unexpected_checksum_finding(&path, observed_at)?);
        }
    }
    Ok((findings, result.truncated, result.scanned_entries))
}

fn checksum_json_format_is_unsupported(output: &ExecOutput) -> bool {
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    combined.contains("--format")
        && (combined.contains("unknown")
            || combined.contains("unrecognized")
            || combined.contains("invalid"))
}

fn checksum_command_error(command: &RemoteCommand, output: &ExecOutput) -> AppError {
    AppError::ssh(
        "command_failed",
        "De servercontrole kon niet worden voltooid.",
        format!(
            "Actie: {}; exitstatus: {}; stdout: {}; stderr: {}",
            command.action_name,
            output.exit_code,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        true,
    )
}

fn checksum_parse_error(
    command: &RemoteCommand,
    output: &ExecOutput,
    parser_error: AppError,
) -> AppError {
    AppError::ssh(
        "checksum_output_invalid",
        "De checksumresultaten konden niet veilig worden gelezen.",
        format!(
            "Actie: {}; exitstatus: {}; parser: {}; stdout: {}; stderr: {}",
            command.action_name,
            output.exit_code,
            parser_error
                .safe_diagnostic()
                .unwrap_or(parser_error.category),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        true,
    )
}

fn checksum_scan_message(title: &str, detail: String, observed_at: &str) -> Finding {
    Finding {
        id: Some(Uuid::new_v4().to_string()),
        category: "wordpress-core-scan-incomplete".into(),
        severity: FindingSeverity::Attention,
        title: title.into(),
        detail,
        path: None,
        checksum_status: Some(ChecksumStatus::ScanError),
        disposition: crate::models::FindingDisposition::Active,
        exception_id: None,
        trusted_file_id: None,
        policy_reason: None,
        policy_target: None,
        vulnerability: None,
        observed_at: Some(observed_at.into()),
    }
}

fn exclude_child_installation_findings(
    findings: Vec<Finding>,
    excluded_root_directories: &[String],
) -> Vec<Finding> {
    if excluded_root_directories.is_empty() {
        return findings;
    }
    findings
        .into_iter()
        .filter(|finding| {
            if finding.checksum_status != Some(ChecksumStatus::Unexpected) {
                return true;
            }
            let Some(path) = finding.path.as_deref() else {
                return true;
            };
            let normalized = path.strip_prefix("./").unwrap_or(path);
            !excluded_root_directories.iter().any(|directory| {
                normalized == directory
                    || normalized
                        .strip_prefix(directory)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        })
        .collect()
}

fn checksum_findings_check(findings: Vec<Finding>) -> ScanCheck {
    if findings.is_empty() {
        return ScanCheck {
            key: "core_checksum".into(),
            label: "WordPress core".into(),
            status: StepStatus::Success,
            summary: "Correct: geen checksumafwijkingen gevonden.".into(),
            technical_details: None,
            findings,
        };
    }
    let modified = checksum_count(&findings, ChecksumStatus::Modified);
    let missing = checksum_count(&findings, ChecksumStatus::Missing);
    let unexpected = checksum_count(&findings, ChecksumStatus::Unexpected);
    let scan_errors = checksum_count(&findings, ChecksumStatus::ScanError);
    ScanCheck {
        key: "core_checksum".into(),
        label: "WordPress core".into(),
        status: StepStatus::Warning,
        summary: format!(
            "Gewijzigd: {modified} · Ontbreekt: {missing} · Hoort niet aanwezig te zijn: {unexpected} · Scanmeldingen: {scan_errors}"
        ),
        technical_details: None,
        findings,
    }
}

fn checksum_count(findings: &[Finding], status: ChecksumStatus) -> usize {
    findings
        .iter()
        .filter(|finding| finding.checksum_status == Some(status))
        .count()
}

fn failed_checksum_check(error: AppError, observed_at: &str) -> ScanCheck {
    let technical_details = error.safe_diagnostic();
    ScanCheck {
        key: "core_checksum".into(),
        label: "WordPress core".into(),
        status: StepStatus::Failed,
        summary: "Scan mislukt.".into(),
        technical_details,
        findings: vec![Finding {
            id: Some(Uuid::new_v4().to_string()),
            category: "wordpress-core-scan-error".into(),
            severity: FindingSeverity::Problem,
            title: "Scan mislukt".into(),
            detail: error.user_message,
            path: None,
            checksum_status: Some(ChecksumStatus::ScanError),
            disposition: crate::models::FindingDisposition::Active,
            exception_id: None,
            trusted_file_id: None,
            policy_reason: None,
            policy_target: None,
            vulnerability: None,
            observed_at: Some(observed_at.into()),
        }],
    }
}

fn findings_check(
    key: &str,
    label: &str,
    findings: Vec<Finding>,
    noun: &str,
    truncated: bool,
) -> ScanCheck {
    let attention = findings
        .iter()
        .any(|finding| finding.severity != FindingSeverity::Info);
    let suffix = if truncated {
        " Resultaten zijn afgekapt op de veilige limiet."
    } else {
        ""
    };
    ScanCheck {
        key: key.into(),
        label: label.into(),
        status: if attention {
            StepStatus::Warning
        } else {
            StepStatus::Success
        },
        summary: format!("{} {noun} gevonden.{suffix}", findings.len()),
        technical_details: None,
        findings,
    }
}

fn php_inventory_check(mut findings: Vec<Finding>, truncated: bool) -> ScanCheck {
    let total = findings.len();
    let noteworthy = findings
        .iter()
        .filter(|finding| finding.severity != FindingSeverity::Info)
        .count();
    findings.retain(|finding| finding.severity != FindingSeverity::Info);
    let suffix = if truncated {
        " Er zijn meer resultaten dan weergegeven; verfijn de filters."
    } else {
        ""
    };
    ScanCheck {
        key: "php_files".into(),
        label: "PHP in wp-content".into(),
        status: if noteworthy > 0 {
            StepStatus::Warning
        } else {
            StepStatus::Success
        },
        summary: format!(
            "{noteworthy} opvallende bestanden van {} geïnventariseerd.{suffix}",
            total
        ),
        technical_details: None,
        findings,
    }
}

fn failed_check(key: &str, label: &str, error: AppError) -> ScanCheck {
    let technical_details = error.safe_diagnostic();
    ScanCheck {
        key: key.into(),
        label: label.into(),
        status: StepStatus::Failed,
        summary: error.user_message,
        technical_details,
        findings: Vec::new(),
    }
}

fn scan_status(checks: &[ScanCheck]) -> SiteStatus {
    if checks.iter().any(|check| {
        check
            .findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Problem)
    }) {
        SiteStatus::Problem
    } else if checks.iter().any(|check| {
        check.status == StepStatus::Failed
            || check
                .findings
                .iter()
                .any(|finding| finding.severity == FindingSeverity::Attention)
    }) {
        SiteStatus::Attention
    } else {
        SiteStatus::Healthy
    }
}

fn security_summary(checks: &[ScanCheck]) -> &'static str {
    if checks
        .iter()
        .any(|check| check.status == StepStatus::Failed)
    {
        "Scan deels mislukt"
    } else if checks.iter().any(|check| {
        check
            .findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Problem)
    }) {
        "Probleem gevonden"
    } else if checks.iter().any(|check| {
        check
            .findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Attention)
    }) {
        "Aandacht nodig"
    } else {
        "Geen aandachtspunten gevonden"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{AuthMethod, Site},
        ssh::ExecOutput,
    };
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct MockSsh {
        outputs: HashMap<&'static str, ExecOutput>,
        authentications: AtomicUsize,
    }
    impl SshExecutor for MockSsh {
        fn fingerprint(&self, _: &Site) -> Result<String, AppError> {
            Ok("SHA256:test".into())
        }
        fn authenticate(&self, _: &Site, _: Option<&str>) -> Result<(), AppError> {
            self.authentications.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn execute(
            &self,
            _: &Site,
            _: Option<&str>,
            command: &RemoteCommand,
        ) -> Result<ExecOutput, AppError> {
            self.outputs
                .get(command.action_name)
                .cloned()
                .ok_or_else(|| {
                    AppError::validation(format!("Geen fixture voor {}", command.action_name))
                })
        }
        fn download(
            &self,
            _: &Site,
            _: Option<&str>,
            _: &str,
            _: &std::path::Path,
        ) -> Result<u64, AppError> {
            Err(AppError::validation("Geen downloadfixture"))
        }
    }
    fn stored() -> StoredSite {
        StoredSite {
            site: Site {
                id: "site".into(),
                name: "Test".into(),
                url: "https://example.test".into(),
                ssh_host: "example.test".into(),
                ssh_port: 22,
                ssh_username: "deploy".into(),
                auth_method: AuthMethod::Password,
                key_path: None,
                wordpress_path: "/var/www".into(),
                parent_site_id: None,
                relation_type: None,
                parent_directory: None,
                pinned_host_key: Some("SHA256:test".into()),
                status: SiteStatus::Unscanned,
                wordpress_version: None,
                php_version: None,
                wp_cli_version: None,
                wp_cli_version_checked_at: None,
                update_count: 0,
                security_status: None,
                last_scan_at: None,
                last_maintenance_at: None,
                created_at: utc_now(),
                updated_at: utc_now(),
                vulnerability_summary: None,
            },
            credential_ref: None,
        }
    }
    fn output(text: &str) -> ExecOutput {
        ExecOutput {
            stdout: text.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
            truncated: false,
        }
    }

    fn failed_output(stderr: &str) -> ExecOutput {
        ExecOutput {
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
            exit_code: 1,
            truncated: false,
        }
    }

    #[test]
    fn checksum_scan_falls_back_for_older_wp_cli_output() {
        let ssh = MockSsh {
            outputs: HashMap::from([
                (
                    "VerifyCoreChecksums",
                    failed_output("Error: Parameter errors: unknown --format parameter"),
                ),
                (
                    "VerifyCoreChecksumsPlain",
                    failed_output(
                        "Warning: File should not exist: wp-admin/extra.php\nError: WordPress installation doesn't verify against checksums.",
                    ),
                ),
                (
                    "FindUnexpectedRootFiles",
                    output(r#"{"files":[],"truncated":false,"scanned_entries":12}"#),
                ),
            ]),
            authentications: AtomicUsize::new(0),
        };

        let site = stored();
        let mut connection = ssh.open_connection(&site.site, Some("secret")).unwrap();
        let check = checksum_check(connection.as_mut(), &site, &[]);
        assert_eq!(check.status, StepStatus::Warning);
        assert_eq!(check.findings.len(), 1);
        assert_eq!(
            check.findings[0].checksum_status,
            Some(ChecksumStatus::Unexpected)
        );
    }

    #[test]
    fn genuine_checksum_failure_does_not_start_the_plain_fallback() {
        let ssh = MockSsh {
            outputs: HashMap::from([(
                "VerifyCoreChecksums",
                failed_output("Error: checksum service is unavailable"),
            )]),
            authentications: AtomicUsize::new(0),
        };

        let site = stored();
        let mut connection = ssh.open_connection(&site.site, Some("secret")).unwrap();
        let check = checksum_check(connection.as_mut(), &site, &[]);
        assert_eq!(check.status, StepStatus::Failed);
        let details = check.technical_details.unwrap();
        assert!(details.contains("VerifyCoreChecksums"));
        assert!(details.contains("checksum service is unavailable"));
    }

    #[test]
    fn root_file_scan_adds_unknown_files_but_defensively_filters_child_paths() {
        let ssh = MockSsh {
            outputs: HashMap::from([
                (
                    "VerifyCoreChecksums",
                    output("Success: WordPress installation verifies against checksums."),
                ),
                (
                    "FindUnexpectedRootFiles",
                    output(
                        r#"{"files":["academy/should-never-return.php","logs/error.php"],"truncated":false,"scanned_entries":24}"#,
                    ),
                ),
            ]),
            authentications: AtomicUsize::new(0),
        };

        let site = stored();
        let mut connection = ssh.open_connection(&site.site, Some("secret")).unwrap();
        let check = checksum_check(connection.as_mut(), &site, &["academy".into()]);
        assert_eq!(check.status, StepStatus::Warning);
        assert_eq!(check.findings.len(), 1);
        assert_eq!(check.findings[0].path.as_deref(), Some("logs/error.php"));
    }

    #[test]
    fn child_scan_without_parent_exclusions_keeps_findings_in_its_own_root() {
        let ssh = MockSsh {
            outputs: HashMap::from([
                (
                    "VerifyCoreChecksums",
                    output("Success: WordPress installation verifies against checksums."),
                ),
                (
                    "FindUnexpectedRootFiles",
                    output(
                        r#"{"files":["academy/diagnostic.php"],"truncated":false,"scanned_entries":8}"#,
                    ),
                ),
            ]),
            authentications: AtomicUsize::new(0),
        };

        let site = stored();
        let mut connection = ssh.open_connection(&site.site, Some("secret")).unwrap();
        let check = checksum_check(connection.as_mut(), &site, &[]);
        assert_eq!(check.findings.len(), 1);
        assert_eq!(
            check.findings[0].path.as_deref(),
            Some("academy/diagnostic.php")
        );
    }

    #[test]
    fn failed_scan_check_keeps_safe_technical_diagnostics() {
        let check = failed_check(
            "php_files",
            "PHP in wp-content",
            AppError::command_failed("FindPhpFiles", 1, "head: invalid option -- z"),
        );
        assert_eq!(check.status, StepStatus::Failed);
        assert!(
            check
                .technical_details
                .as_deref()
                .unwrap()
                .contains("head: invalid option -- z")
        );
    }

    #[test]
    fn update_checks_use_mocked_allowlisted_commands() {
        let ssh = MockSsh {
            outputs: HashMap::from([
                ("GetWordPressVersion", output("6.8.1")),
                ("CheckCoreUpdates", output(r#"[{"version":"6.8.2"}]"#)),
                (
                    "ListPluginUpdates",
                    output(r#"[{"name":"seo","title":"SEO","version":"1","update_version":"2"}]"#),
                ),
                ("ListThemeUpdates", output("[]")),
            ]),
            authentications: AtomicUsize::new(0),
        };
        let updates = check_updates(&ssh, &stored(), Some("secret")).unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[1].slug, "seo");
        assert_eq!(ssh.authentications.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn full_scan_authenticates_once_and_reports_each_expensive_step() {
        let ssh = MockSsh {
            outputs: HashMap::from([
                ("GetWordPressVersion", output("6.8.2")),
                ("DetectWordPress", output("1")),
                ("GetPhpVersion", output("8.3.12")),
                ("GetWpCliVersion", output("WP-CLI 2.12.0")),
                (
                    "VerifyCoreChecksums",
                    output("Success: WordPress installation verifies against checksums."),
                ),
                (
                    "FindUnexpectedRootFiles",
                    output(r#"{"files":[],"truncated":false,"scanned_entries":12}"#),
                ),
                ("ListUsers", output("[]")),
                ("FindPhpFiles", output("")),
                ("FindPhpInUploads", output("")),
                ("FindModifiedFiles", output("")),
                ("CheckUnsafePermissions", output("")),
                (
                    "CheckSelectedWpConfigConstants",
                    output(
                        r#"{"WP_DEBUG":false,"DISALLOW_FILE_EDIT":true,"WP_ENVIRONMENT_TYPE":"production"}"#,
                    ),
                ),
                (
                    "ListCronEvents",
                    output(
                        r#"[{"hook":"wp_update_plugins","timestamp":1789462800,"schedule":"twicedaily","interval":43200,"args":[]}]"#,
                    ),
                ),
                ("CheckDatabase", output("Success: Database checked.")),
                ("CheckCoreUpdates", output("[]")),
                (
                    "ListPluginUpdates",
                    output(
                        r#"[{"name":"object-cache.php","title":"","status":"dropin","version":"","update":"none","update_version":""}]"#,
                    ),
                ),
                ("ListThemeUpdates", output("[]")),
            ]),
            authentications: AtomicUsize::new(0),
        };
        let mut stored = stored();
        stored.site.url = "http://127.0.0.1:9".into();
        let mut progress = RecordingProgress::default();

        let outcome =
            scan_site_with_progress(&ssh, &stored, Some("secret"), 30, &mut progress).unwrap();

        assert_eq!(ssh.authentications.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.wordpress_version, "6.8.2");
        assert_eq!(outcome.wp_cli_version.as_deref(), Some("WP-CLI 2.12.0"));
        assert!(outcome.updates.as_ref().is_some_and(Vec::is_empty));
        assert!(outcome.inventory.iter().any(|item| {
            item.slug == "object-cache.php"
                && item.name == "object-cache.php"
                && item.status == "dropin"
                && item.version == "onbekend"
        }));
        assert!(matches!(
            outcome.snapshot_sections.cron,
            SnapshotBuildSection::Complete(ref events) if events.len() == 1
        ));
        assert_eq!(
            progress.started.first().map(String::as_str),
            Some("ssh_connect")
        );
        assert!(progress.started.contains(&"plugin_list".into()));
        assert!(progress.started.contains(&"homepage".into()));
        assert_eq!(progress.started.len(), progress.finished.len());
        eprintln!("synthetic_scan_timings={:?}", progress.finished);
    }

    #[test]
    fn wp_cli_version_is_normalized_for_storage_and_display() {
        assert_eq!(
            normalize_wp_cli_version("2.12.0\n").as_deref(),
            Some("WP-CLI 2.12.0")
        );
        assert_eq!(
            normalize_wp_cli_version("WP-CLI 2.12.0\n").as_deref(),
            Some("WP-CLI 2.12.0")
        );
        assert_eq!(normalize_wp_cli_version("  "), None);
    }

    #[test]
    fn wp_cli_version_failure_is_a_non_blocking_warning() {
        let mut progress = RecordingProgress::default();
        let version = measured_wp_cli_version(&mut progress, || {
            Err(AppError::command_failed(
                "GetWpCliVersion",
                127,
                "wp: command not found",
            ))
        })
        .unwrap();

        assert_eq!(version, None);
        assert_eq!(progress.started, ["wp_cli_version"]);
        assert!(matches!(
            progress.finished.as_slice(),
            [(key, StepStatus::Warning, _)] if key == "wp_cli_version"
        ));
    }

    #[test]
    fn confirmed_child_directories_hide_only_their_unexpected_checksum_findings() {
        let findings = parsers::parse_checksum_output(
            r#"[
                {"file":"dev/wp-admin/load.php","message":"File should not exist"},
                {"file":"portal/index.php","message":"File should not exist"},
                {"file":"dev/wp-includes/version.php","message":"File doesn't verify against checksum"}
            ]"#,
            "2026-09-21T08:00:00Z",
        )
        .unwrap();
        let filtered = exclude_child_installation_findings(findings, &["dev".into()]);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|finding| {
            finding.path.as_deref() == Some("portal/index.php")
                && finding.checksum_status == Some(ChecksumStatus::Unexpected)
        }));
        assert!(filtered.iter().any(|finding| {
            finding.path.as_deref() == Some("dev/wp-includes/version.php")
                && finding.checksum_status == Some(ChecksumStatus::Modified)
        }));
    }

    #[derive(Default)]
    struct RecordingProgress {
        started: Vec<String>,
        finished: Vec<(String, StepStatus, u64)>,
        failed_diagnostics: Vec<(String, String, Option<String>)>,
    }

    impl ScanProgress for RecordingProgress {
        fn step_started(&mut self, key: &str) {
            self.started.push(key.into());
        }

        fn step_finished(
            &mut self,
            key: &str,
            status: StepStatus,
            duration_ms: u64,
            _detail: Option<String>,
        ) {
            self.finished.push((key.into(), status, duration_ms));
        }

        fn step_failed_diagnostic(
            &mut self,
            key: &str,
            user_message: &str,
            technical_details: Option<&str>,
            _duration_ms: u64,
        ) {
            self.failed_diagnostics.push((
                key.into(),
                user_message.into(),
                technical_details.map(str::to_owned),
            ));
        }
    }

    #[test]
    fn failed_scan_progress_receives_the_real_checksum_diagnostic() {
        let mut progress = RecordingProgress::default();
        let check = measured_check(&mut progress, "checksum", || {
            failed_checksum_check(
                AppError::command_failed("VerifyCoreChecksums", 70, "remote checksum error"),
                "2026-09-21T08:00:00Z",
            )
        })
        .unwrap();

        assert_eq!(check.status, StepStatus::Failed);
        assert!(matches!(
            progress.failed_diagnostics.as_slice(),
            [(key, _, Some(details))]
                if key == "checksum"
                    && details.contains("VerifyCoreChecksums")
                    && details.contains("remote checksum error")
        ));
    }

    #[test]
    fn arbitrary_update_kinds_are_rejected() {
        let ssh = MockSsh {
            outputs: HashMap::new(),
            authentications: AtomicUsize::new(0),
        };
        let error = run_update(&ssh, &stored(), None, "shell", Some("id")).unwrap_err();
        assert_eq!(error.category, "validation");
    }
}
