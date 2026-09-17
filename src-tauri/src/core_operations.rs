use crate::{
    backup::{BackupResult, create_database_backup},
    command_catalog::{RemoteAction, build},
    database::utc_now,
    engine::{self, ScanOutcome, checked_output},
    error::AppError,
    health::{HealthCheck, check_homepage},
    models::{
        CoreOperationInfo, CoreOperationKind, MaintenanceRun, MaintenanceStep, StepStatus,
        StoredSite, UpdateItem, UpdateKind,
    },
    ssh::SshExecutor,
    validation::{validate_wordpress_locale, validate_wordpress_version},
};
use std::{path::Path, time::Instant};
use uuid::Uuid;

const MIN_DISK_MB: u64 = 100;

#[derive(Debug, PartialEq, Eq)]
struct DiskSpaceCheck {
    available_kb: Option<u64>,
    warning: Option<String>,
}

impl DiskSpaceCheck {
    fn available(available_kb: u64) -> Self {
        Self {
            available_kb: Some(available_kb),
            warning: None,
        }
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            available_kb: None,
            warning: Some(format!(
                "De vrije schijfruimte kon niet betrouwbaar worden bepaald: {}. De coreactie wordt hierdoor niet geblokkeerd; controleer de beschikbare ruimte zo nodig handmatig.",
                reason.into()
            )),
        }
    }
}

fn parse_disk_space(output: &str) -> DiskSpaceCheck {
    for (prefix, divisor) in [("WPMM_PHP_BYTES:", 1024), ("WPMM_WP_BYTES:", 1024)] {
        if let Some(value) = output
            .lines()
            .find_map(|line| line.trim().strip_prefix(prefix))
        {
            return value
                .trim()
                .parse::<u64>()
                .ok()
                .map(|bytes| DiskSpaceCheck::available(bytes / divisor))
                .unwrap_or_else(|| {
                    DiskSpaceCheck::unavailable(
                        "de PHP-fallback gaf geen geldige numerieke waarde terug",
                    )
                });
        }
    }

    if let Some(statuses) = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("WPMM_DISK_UNAVAILABLE:"))
    {
        let provider_status = |key: &str, label: &str| {
            let status = statuses
                .split(';')
                .find_map(|item| item.trim().strip_prefix(&format!("{key}=")))
                .unwrap_or("onbekend");
            if status == "127" {
                format!("{label} niet beschikbaar (exitstatus 127)")
            } else {
                format!("{label} mislukt (exitstatus {status})")
            }
        };
        return DiskSpaceCheck::unavailable(format!(
            "{}; {}; {}",
            provider_status("df", "df"),
            provider_status("php", "PHP"),
            provider_status("wp", "WP-CLI-fallback")
        ));
    }

    let Some(data_line) = output
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .last()
    else {
        return DiskSpaceCheck::unavailable(
            "df gaf geen gegevensregel terug voor het opgegeven WordPress-pad",
        );
    };
    let fields = data_line.split_whitespace().collect::<Vec<_>>();
    let Some(available) = fields
        .len()
        .checked_sub(3)
        .and_then(|index| fields.get(index))
    else {
        return DiskSpaceCheck::unavailable(
            "de gegevensregel van df bevat geen kolom voor beschikbare ruimte",
        );
    };
    available
        .parse::<u64>()
        .ok()
        .map(DiskSpaceCheck::available)
        .unwrap_or_else(|| {
            DiskSpaceCheck::unavailable(
                "de kolom voor beschikbare ruimte in de df-uitvoer is niet numeriek",
            )
        })
}

pub struct CoreOperationOutcome {
    pub run: MaintenanceRun,
    pub backup: Option<BackupResult>,
    pub scan: Option<ScanOutcome>,
    pub updates_after: Vec<UpdateItem>,
    pub current_version: String,
}

pub fn inspect(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
) -> Result<CoreOperationInfo, AppError> {
    executor.authenticate(&stored.site, credential)?;
    engine::text_action(executor, stored, credential, RemoteAction::DetectWordPress)?;
    engine::text_action(executor, stored, credential, RemoteAction::GetWpCliVersion)?;
    engine::text_action(executor, stored, credential, RemoteAction::CheckDatabase)?;
    let current_version = engine::text_action(
        executor,
        stored,
        credential,
        RemoteAction::GetWordPressVersion,
    )?
    .trim()
    .to_owned();
    validate_wordpress_version(&current_version)?;
    let locale = engine::text_action(executor, stored, credential, RemoteAction::GetCoreLocale)?
        .trim()
        .to_owned();
    validate_wordpress_locale(&locale)?;
    let disk_output =
        engine::text_action(executor, stored, credential, RemoteAction::CheckDiskSpace)?;
    let disk_space = parse_disk_space(&disk_output);
    let disk_available_mb = disk_space
        .available_kb
        .map(|available_kb| available_kb / 1024);
    if disk_available_mb.is_some_and(|available_mb| available_mb < MIN_DISK_MB) {
        return Err(AppError::validation(format!(
            "Er is minder dan {MIN_DISK_MB} MB vrije schijfruimte beschikbaar voor de coreactie."
        )));
    }
    if let Some(warning) = disk_space.warning.as_deref() {
        eprintln!(
            "site_id={} action=CheckDiskSpace status=unavailable detail={warning}",
            stored.site.id
        );
    }
    let updates = engine::check_updates(executor, stored, credential)?;
    let available_version = updates
        .iter()
        .find(|update| update.kind == UpdateKind::Core)
        .map(|update| update.new_version.clone());
    if let Some(version) = available_version.as_deref() {
        validate_wordpress_version(version)?;
    }
    Ok(CoreOperationInfo {
        current_version,
        locale,
        wordpress_path: stored.site.wordpress_path.clone(),
        available_version,
        disk_available_mb,
        disk_space_warning: disk_space.warning,
    })
}

pub fn new_run(stored: &StoredSite, kind: CoreOperationKind) -> MaintenanceRun {
    let definitions: &[(&str, &str)] = match kind {
        CoreOperationKind::Repair => &[
            ("preflight", "Preflight"),
            ("backup", "Databasebackup"),
            ("repair", "Officiële corebestanden opnieuw installeren"),
            ("checksum", "Core checksum"),
            ("version", "WordPress-versie"),
            ("database_check", "Databasecontrole"),
            ("homepage", "Homepage bereikbaar"),
            ("updates", "Updatecontrole"),
        ],
        CoreOperationKind::Update => &[
            ("preflight", "Preflight"),
            ("backup", "Databasebackup"),
            ("core", "WordPress core bijwerken"),
            ("database_update", "WordPress database bijwerken"),
            ("languages", "Corevertalingen bijwerken"),
            ("checksum", "Core checksum"),
            ("version", "WordPress-versie"),
            ("database_check", "Databasecontrole"),
            ("homepage", "Homepage bereikbaar"),
            ("updates", "Updatecontrole"),
        ],
    };
    MaintenanceRun {
        id: Uuid::new_v4().to_string(),
        site_id: stored.site.id.clone(),
        site_name: Some(stored.site.name.clone()),
        started_at: utc_now(),
        finished_at: None,
        status: StepStatus::Running,
        duration_ms: None,
        backup_path: None,
        steps: definitions
            .iter()
            .map(|(key, label)| MaintenanceStep {
                key: (*key).into(),
                label: (*label).into(),
                status: StepStatus::Pending,
                detail: None,
            })
            .collect(),
        before_versions: None,
        after_versions: None,
    }
}

pub fn execute<F>(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    backup_root: &Path,
    kind: CoreOperationKind,
    run: MaintenanceRun,
    progress: F,
) -> Result<CoreOperationOutcome, AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
{
    execute_with_health(
        executor,
        stored,
        credential,
        backup_root,
        kind,
        run,
        progress,
        check_homepage,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_with_health<F, H>(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    backup_root: &Path,
    kind: CoreOperationKind,
    mut run: MaintenanceRun,
    mut progress: F,
    mut health_check: H,
) -> Result<CoreOperationOutcome, AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
    H: FnMut(&str) -> Result<HealthCheck, AppError>,
{
    let timer = Instant::now();
    let mut backup = None;
    let mut scan = None;

    set_step(
        &mut run,
        "preflight",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    let info = match inspect(executor, stored, credential) {
        Ok(info) => info,
        Err(error) => {
            fail_and_skip(
                &mut run,
                "preflight",
                error.user_message,
                timer,
                &mut progress,
            )?;
            return Ok(empty_outcome(run, backup, scan));
        }
    };
    if kind == CoreOperationKind::Update && info.available_version.is_none() {
        fail_and_skip(
            &mut run,
            "preflight",
            "Er is geen WordPress core-update beschikbaar.".into(),
            timer,
            &mut progress,
        )?;
        return Ok(outcome_with_version(
            run,
            backup,
            scan,
            &info.current_version,
        ));
    }
    run.before_versions = Some(format!(
        "WordPress {} · locale {}",
        info.current_version, info.locale
    ));
    let disk_summary = info.disk_available_mb.map_or_else(
        || "vrije ruimte niet vastgesteld (niet blokkerend)".into(),
        |available_mb| format!("{available_mb} MB vrij"),
    );
    let disk_warning = info
        .disk_space_warning
        .as_deref()
        .map_or_else(String::new, |warning| format!(" Waarschuwing: {warning}"));
    set_step(
        &mut run,
        "preflight",
        StepStatus::Success,
        Some(format!(
            "WordPress {}; locale {}; root {}; {}{}.{}",
            info.current_version,
            info.locale,
            info.wordpress_path,
            disk_summary,
            info.available_version
                .as_deref()
                .map_or_else(String::new, |version| format!(
                    "; update {version} beschikbaar"
                )),
            disk_warning
        )),
        &mut progress,
    )?;

    set_step(&mut run, "backup", StepStatus::Running, None, &mut progress)?;
    match create_database_backup(executor, stored, credential, backup_root) {
        Ok(created) => {
            run.backup_path = Some(created.local_path.clone());
            set_step(
                &mut run,
                "backup",
                StepStatus::Success,
                Some(format!(
                    "Lokale gzipbackup gemaakt ({} bytes).",
                    created.size_bytes
                )),
                &mut progress,
            )?;
            backup = Some(created);
        }
        Err(error) => {
            fail_and_skip(
                &mut run,
                "backup",
                format!("Backup mislukt — coreactie gestopt. {}", error.user_message),
                timer,
                &mut progress,
            )?;
            return Ok(outcome_with_version(
                run,
                backup,
                scan,
                &info.current_version,
            ));
        }
    }

    let (mutation_key, mutation_action, mutation_detail) = match kind {
        CoreOperationKind::Repair => (
            "repair",
            RemoteAction::RepairCore {
                version: info.current_version.clone(),
                locale: info.locale.clone(),
            },
            format!(
                "Officiële WordPress {}-bestanden opnieuw geïnstalleerd; wp-content en onbekende bestanden zijn behouden.",
                info.current_version
            ),
        ),
        CoreOperationKind::Update => {
            let target = info.available_version.clone().ok_or_else(|| {
                AppError::validation("Er is geen WordPress core-update beschikbaar.")
            })?;
            (
                "core",
                RemoteAction::UpdateCoreTo {
                    version: target.clone(),
                },
                format!("WordPress core bijgewerkt naar {target}."),
            )
        }
    };
    set_step(
        &mut run,
        mutation_key,
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    if let Err(error) = run_action(executor, stored, credential, mutation_action) {
        fail_and_skip(
            &mut run,
            mutation_key,
            error.user_message,
            timer,
            &mut progress,
        )?;
        return Ok(outcome_with_version(
            run,
            backup,
            scan,
            &info.current_version,
        ));
    }
    set_step(
        &mut run,
        mutation_key,
        StepStatus::Success,
        Some(mutation_detail),
        &mut progress,
    )?;

    if kind == CoreOperationKind::Update {
        run_noncritical_action(
            executor,
            stored,
            credential,
            &mut run,
            "database_update",
            RemoteAction::UpdateDatabase,
            "WordPress databaseschema bijgewerkt.",
            &mut progress,
        )?;
        run_noncritical_action(
            executor,
            stored,
            credential,
            &mut run,
            "languages",
            RemoteAction::UpdateCoreLanguages,
            "Corevertalingen bijgewerkt.",
            &mut progress,
        )?;
    }

    set_step(
        &mut run,
        "checksum",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    match engine::scan_site(executor, stored, credential, 30) {
        Ok(outcome) => {
            let checksum = outcome
                .result
                .checks
                .iter()
                .find(|check| check.key == "core_checksum");
            let status = checksum.map_or(StepStatus::Failed, |check| check.status);
            let detail = checksum.map_or_else(
                || "De checksumcontrole ontbreekt in het scanresultaat.".into(),
                |check| check.summary.clone(),
            );
            scan = Some(outcome);
            set_step(&mut run, "checksum", status, Some(detail), &mut progress)?;
        }
        Err(error) => set_step(
            &mut run,
            "checksum",
            StepStatus::Failed,
            Some(error.user_message),
            &mut progress,
        )?,
    }

    set_step(
        &mut run,
        "version",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    let current_version = match engine::text_action(
        executor,
        stored,
        credential,
        RemoteAction::GetWordPressVersion,
    ) {
        Ok(version) => {
            let version = version.trim().to_owned();
            let expected = match kind {
                CoreOperationKind::Repair => info.current_version.as_str(),
                CoreOperationKind::Update => info
                    .available_version
                    .as_deref()
                    .unwrap_or(&info.current_version),
            };
            let status = if version == expected {
                StepStatus::Success
            } else {
                StepStatus::Warning
            };
            set_step(
                &mut run,
                "version",
                status,
                Some(format!("WordPress {version}; verwacht {expected}.")),
                &mut progress,
            )?;
            version
        }
        Err(error) => {
            set_step(
                &mut run,
                "version",
                StepStatus::Failed,
                Some(error.user_message),
                &mut progress,
            )?;
            info.current_version.clone()
        }
    };

    run_noncritical_action(
        executor,
        stored,
        credential,
        &mut run,
        "database_check",
        RemoteAction::CheckDatabase,
        "Databasecontrole voltooid.",
        &mut progress,
    )?;

    set_step(
        &mut run,
        "homepage",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    match health_check(&stored.site.url) {
        Ok(health) => {
            let status = if health.reachable
                && health
                    .status_code
                    .is_some_and(|code| (200..400).contains(&code))
            {
                StepStatus::Success
            } else {
                StepStatus::Warning
            };
            set_step(
                &mut run,
                "homepage",
                status,
                Some(health.detail),
                &mut progress,
            )?;
        }
        Err(error) => set_step(
            &mut run,
            "homepage",
            StepStatus::Failed,
            Some(error.user_message),
            &mut progress,
        )?,
    }

    set_step(
        &mut run,
        "updates",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    let updates_after = match engine::check_updates(executor, stored, credential) {
        Ok(updates) => {
            set_step(
                &mut run,
                "updates",
                StepStatus::Success,
                Some(format!("{} updates beschikbaar na afloop.", updates.len())),
                &mut progress,
            )?;
            updates
        }
        Err(error) => {
            set_step(
                &mut run,
                "updates",
                StepStatus::Failed,
                Some(error.user_message),
                &mut progress,
            )?;
            Vec::new()
        }
    };
    run.after_versions = Some(format!(
        "WordPress {current_version} · {} updates beschikbaar",
        updates_after.len()
    ));
    let final_status = if run
        .steps
        .iter()
        .any(|step| matches!(step.status, StepStatus::Warning | StepStatus::Failed))
    {
        StepStatus::Warning
    } else {
        StepStatus::Success
    };
    finish(&mut run, final_status, timer);
    Ok(CoreOperationOutcome {
        run,
        backup,
        scan,
        updates_after,
        current_version,
    })
}

fn run_action(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    action: RemoteAction,
) -> Result<(), AppError> {
    let command = build(&stored.site.wordpress_path, action)?;
    if !command.mutating {
        return Err(AppError::validation(
            "De coreactie is niet als muterende actie geregistreerd.",
        ));
    }
    checked_output(executor, &stored.site, credential, command).map(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn run_noncritical_action<F>(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    run: &mut MaintenanceRun,
    key: &str,
    action: RemoteAction,
    success_detail: &str,
    progress: &mut F,
) -> Result<(), AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
{
    set_step(run, key, StepStatus::Running, None, progress)?;
    let result = if action_is_mutating(&action) {
        run_action(executor, stored, credential, action)
    } else {
        engine::text_action(executor, stored, credential, action).map(|_| ())
    };
    match result {
        Ok(()) => set_step(
            run,
            key,
            StepStatus::Success,
            Some(success_detail.into()),
            progress,
        ),
        Err(error) => set_step(
            run,
            key,
            StepStatus::Failed,
            Some(error.user_message),
            progress,
        ),
    }
}

fn action_is_mutating(action: &RemoteAction) -> bool {
    matches!(
        action,
        RemoteAction::UpdateDatabase | RemoteAction::UpdateCoreLanguages
    )
}

fn set_step<F>(
    run: &mut MaintenanceRun,
    key: &str,
    status: StepStatus,
    detail: Option<String>,
    progress: &mut F,
) -> Result<(), AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
{
    let step = run
        .steps
        .iter_mut()
        .find(|step| step.key == key)
        .ok_or_else(|| AppError::validation("Onbekende coreoperatiestap."))?;
    step.status = status;
    step.detail = detail;
    progress(step)
}

fn fail_and_skip<F>(
    run: &mut MaintenanceRun,
    failed_key: &str,
    detail: String,
    timer: Instant,
    progress: &mut F,
) -> Result<(), AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
{
    set_step(run, failed_key, StepStatus::Failed, Some(detail), progress)?;
    let position = run
        .steps
        .iter()
        .position(|step| step.key == failed_key)
        .unwrap_or(0);
    for step in run.steps.iter_mut().skip(position + 1) {
        step.status = StepStatus::Skipped;
        step.detail = Some("Niet uitgevoerd omdat een kritieke eerdere stap mislukte.".into());
        progress(step)?;
    }
    finish(run, StepStatus::Failed, timer);
    Ok(())
}

fn finish(run: &mut MaintenanceRun, status: StepStatus, timer: Instant) {
    run.status = status;
    run.finished_at = Some(utc_now());
    run.duration_ms = Some(timer.elapsed().as_millis().min(u64::MAX as u128) as u64);
}

fn empty_outcome(
    run: MaintenanceRun,
    backup: Option<BackupResult>,
    scan: Option<ScanOutcome>,
) -> CoreOperationOutcome {
    CoreOperationOutcome {
        run,
        backup,
        scan,
        updates_after: Vec::new(),
        current_version: "onbekend".into(),
    }
}

fn outcome_with_version(
    run: MaintenanceRun,
    backup: Option<BackupResult>,
    scan: Option<ScanOutcome>,
    version: &str,
) -> CoreOperationOutcome {
    CoreOperationOutcome {
        run,
        backup,
        scan,
        updates_after: Vec::new(),
        current_version: version.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command_catalog::RemoteCommand,
        models::{AuthMethod, Site, SiteStatus},
        ssh::ExecOutput,
    };
    use std::{fs, path::Path, sync::Mutex};

    struct CoreMockSsh {
        actions: Mutex<Vec<String>>,
        auth_fails: bool,
        backup_fails: bool,
        mutation_fails: bool,
        checksum: String,
        disk_output: String,
        update_available: bool,
        updated: Mutex<bool>,
    }

    impl SshExecutor for CoreMockSsh {
        fn fingerprint(&self, _: &Site) -> Result<String, AppError> {
            Ok("SHA256:test".into())
        }

        fn authenticate(&self, _: &Site, _: Option<&str>) -> Result<(), AppError> {
            if self.auth_fails {
                Err(AppError::ssh(
                    "ssh_disconnect",
                    "De SSH-verbinding werd verbroken.",
                    "connection reset",
                    true,
                ))
            } else {
                Ok(())
            }
        }

        fn execute(
            &self,
            _: &Site,
            _: Option<&str>,
            command: &RemoteCommand,
        ) -> Result<ExecOutput, AppError> {
            self.actions
                .lock()
                .unwrap()
                .push(command.action_name.into());
            if self.backup_fails && command.action_name == "CreateDatabaseBackup" {
                return Ok(failed("backup failed"));
            }
            if self.mutation_fails && matches!(command.action_name, "RepairCore" | "UpdateCoreTo") {
                return Ok(failed("download failed"));
            }
            if command.action_name == "UpdateCoreTo" {
                *self.updated.lock().unwrap() = true;
            }
            let updated = *self.updated.lock().unwrap();
            let stdout = match command.action_name {
                "GetWordPressVersion" => {
                    if updated { "6.9.0" } else { "6.8.2" }.into()
                }
                "GetWpCliVersion" => "WP-CLI 2.12.0".into(),
                "GetCoreLocale" => "nl_NL".into(),
                "CheckDiskSpace" => self.disk_output.clone(),
                "CheckCoreUpdates" => {
                    if self.update_available && !updated {
                        r#"[{"version":"6.9.0"}]"#.into()
                    } else {
                        "[]".into()
                    }
                }
                "ListPluginUpdates" | "ListThemeUpdates" | "ListUsers" => "[]".into(),
                "VerifyCoreChecksums" => self.checksum.clone(),
                "CheckSelectedWpConfigConstants" => r#"{"WP_DEBUG":false,"DISALLOW_FILE_EDIT":true,"WP_ENVIRONMENT_TYPE":"production"}"#.into(),
                "CreateDatabaseBackup" => "/tmp/wpmm-Ab12Cd34.sql".into(),
                _ => String::new(),
            };
            Ok(success(&stdout))
        }

        fn download(
            &self,
            _: &Site,
            _: Option<&str>,
            _: &str,
            local_path: &Path,
        ) -> Result<u64, AppError> {
            fs::write(local_path, b"mock gzip database backup")?;
            Ok(25)
        }
    }

    fn success(text: &str) -> ExecOutput {
        ExecOutput {
            stdout: text.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_code: 0,
            truncated: false,
        }
    }

    fn failed(text: &str) -> ExecOutput {
        ExecOutput {
            stdout: Vec::new(),
            stderr: text.as_bytes().to_vec(),
            exit_code: 1,
            truncated: false,
        }
    }

    fn stored() -> StoredSite {
        StoredSite {
            site: Site {
                id: Uuid::new_v4().to_string(),
                name: "Core test".into(),
                url: "https://example.test".into(),
                ssh_host: "example.test".into(),
                ssh_port: 22,
                ssh_username: "deploy".into(),
                auth_method: AuthMethod::KeyFile,
                key_path: Some("key".into()),
                wordpress_path: "/srv/site".into(),
                pinned_host_key: Some("SHA256:test".into()),
                status: SiteStatus::Healthy,
                wordpress_version: Some("6.8.2".into()),
                php_version: Some("8.3".into()),
                wp_cli_version: Some("WP-CLI 2.12.0".into()),
                wp_cli_version_checked_at: Some("now".into()),
                update_count: 0,
                security_status: None,
                last_scan_at: None,
                last_maintenance_at: None,
                created_at: "now".into(),
                updated_at: "now".into(),
                vulnerability_summary: None,
            },
            credential_ref: None,
        }
    }

    fn mock(backup_fails: bool, mutation_fails: bool, update_available: bool) -> CoreMockSsh {
        CoreMockSsh {
            actions: Mutex::new(Vec::new()),
            auth_fails: false,
            backup_fails,
            mutation_fails,
            checksum: "Success: WordPress installation verifies against checksums.".into(),
            disk_output: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 2097152 1048576 1048576 50% /srv/site\n".into(),
            update_available,
            updated: Mutex::new(false),
        }
    }

    fn healthy(_: &str) -> Result<HealthCheck, AppError> {
        Ok(HealthCheck {
            reachable: true,
            status_code: Some(200),
            response_time_ms: 10,
            detail: "Homepage bereikbaar met HTTP 200.".into(),
        })
    }

    #[test]
    fn parses_available_space_from_standard_df_output() {
        let output = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 4194304 1048576 3145728 25% /srv/site\n";
        assert_eq!(
            parse_disk_space(output),
            DiskSpaceCheck::available(3_145_728)
        );
    }

    #[test]
    fn parses_available_space_when_df_wraps_the_filesystem_name() {
        let output = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/a-very-long-filesystem-name\n 4194304 1048576 3145728 25% /srv/site\n";
        assert_eq!(
            parse_disk_space(output),
            DiskSpaceCheck::available(3_145_728)
        );
    }

    #[test]
    fn parses_available_space_from_php_fallback() {
        assert_eq!(
            parse_disk_space("WPMM_PHP_BYTES:3221225472\n"),
            DiskSpaceCheck::available(3_145_728)
        );
        assert_eq!(
            parse_disk_space("notice\nWPMM_WP_BYTES:3221225472\n"),
            DiskSpaceCheck::available(3_145_728)
        );
    }

    #[test]
    fn recognizes_exit_127_as_an_unavailable_disk_provider() {
        let result = parse_disk_space("WPMM_DISK_UNAVAILABLE:df=127;php=127;wp=66\n");
        assert_eq!(result.available_kb, None);
        let warning = result.warning.unwrap();
        assert!(warning.contains("df niet beschikbaar (exitstatus 127)"));
        assert!(warning.contains("PHP niet beschikbaar (exitstatus 127)"));
        assert!(warning.contains("WP-CLI-fallback mislukt (exitstatus 66)"));
        assert!(warning.contains("niet geblokkeerd"));
    }

    #[test]
    fn malformed_disk_output_becomes_a_non_blocking_warning() {
        let result =
            parse_disk_space("Filesystem 1024-blocks Used Available Capacity Mounted on\n");
        assert_eq!(result.available_kb, None);
        assert!(result.warning.unwrap().contains("geen gegevensregel"));
    }

    #[test]
    fn inspect_continues_when_all_disk_space_providers_are_unavailable() {
        let mut executor = mock(false, false, false);
        executor.disk_output = "WPMM_DISK_UNAVAILABLE:df=127;php=127;wp=66\n".into();
        let info = inspect(&executor, &stored(), None).unwrap();
        assert_eq!(info.disk_available_mb, None);
        assert!(
            info.disk_space_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("df niet beschikbaar (exitstatus 127)"))
        );
    }

    #[test]
    fn repair_continues_when_disk_space_cannot_be_measured() {
        let mut executor = mock(false, false, false);
        executor.disk_output = "WPMM_DISK_UNAVAILABLE:df=127;php=127;wp=66\n".into();
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Repair,
            new_run(&stored, CoreOperationKind::Repair),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Success);
        assert!(
            executor
                .actions
                .lock()
                .unwrap()
                .contains(&"RepairCore".into())
        );
        assert!(
            result
                .run
                .steps
                .iter()
                .find(|step| step.key == "preflight")
                .and_then(|step| step.detail.as_deref())
                .is_some_and(|detail| detail.contains("niet blokkerend"))
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn known_low_disk_space_still_blocks_the_core_action() {
        let mut executor = mock(false, false, false);
        executor.disk_output = "WPMM_PHP_BYTES:52428800\n".into();
        let error = inspect(&executor, &stored(), None).unwrap_err();
        assert_eq!(error.category, "validation");
        assert!(error.user_message.contains("minder dan 100 MB"));
    }

    #[test]
    fn repair_detects_current_version_locale_and_runs_postchecks() {
        let executor = mock(false, false, false);
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Repair,
            new_run(&stored, CoreOperationKind::Repair),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Success);
        assert_eq!(result.current_version, "6.8.2");
        assert!(result.backup.is_some());
        assert!(result.scan.is_some());
        let actions = executor.actions.lock().unwrap();
        assert!(actions.contains(&"GetCoreLocale".into()));
        assert!(actions.contains(&"RepairCore".into()));
        assert!(actions.contains(&"VerifyCoreChecksums".into()));
        assert!(actions.contains(&"CheckDatabase".into()));
        assert_eq!(
            result
                .run
                .steps
                .iter()
                .find(|step| step.key == "homepage")
                .unwrap()
                .status,
            StepStatus::Success
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn backup_failure_stops_before_repair() {
        let executor = mock(true, false, false);
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Repair,
            new_run(&stored, CoreOperationKind::Repair),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Failed);
        assert!(
            !executor
                .actions
                .lock()
                .unwrap()
                .contains(&"RepairCore".into())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_download_is_recorded_and_stops_postchecks() {
        let executor = mock(false, true, false);
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Repair,
            new_run(&stored, CoreOperationKind::Repair),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Failed);
        assert!(result.scan.is_none());
        assert!(
            !executor
                .actions
                .lock()
                .unwrap()
                .contains(&"VerifyCoreChecksums".into())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn core_update_uses_detected_target_then_db_languages_and_checksum() {
        let executor = mock(false, false, true);
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Update,
            new_run(&stored, CoreOperationKind::Update),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Success);
        assert_eq!(result.current_version, "6.9.0");
        let actions = executor.actions.lock().unwrap();
        let backup = actions
            .iter()
            .position(|action| action == "CreateDatabaseBackup")
            .unwrap();
        let core = actions
            .iter()
            .position(|action| action == "UpdateCoreTo")
            .unwrap();
        let database = actions
            .iter()
            .position(|action| action == "UpdateDatabase")
            .unwrap();
        let languages = actions
            .iter()
            .position(|action| action == "UpdateCoreLanguages")
            .unwrap();
        let checksum = actions
            .iter()
            .position(|action| action == "VerifyCoreChecksums")
            .unwrap();
        assert!(backup < core && core < database && database < languages && languages < checksum);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn already_current_stops_before_backup_and_update() {
        let executor = mock(false, false, false);
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Update,
            new_run(&stored, CoreOperationKind::Update),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Failed);
        let actions = executor.actions.lock().unwrap();
        assert!(!actions.contains(&"CreateDatabaseBackup".into()));
        assert!(!actions.contains(&"UpdateCoreTo".into()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn update_backup_failure_stops_before_core_mutation() {
        let executor = mock(true, false, true);
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Update,
            new_run(&stored, CoreOperationKind::Update),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Failed);
        let actions = executor.actions.lock().unwrap();
        assert!(actions.contains(&"CreateDatabaseBackup".into()));
        assert!(!actions.contains(&"UpdateCoreTo".into()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_core_update_stops_before_database_and_language_updates() {
        let executor = mock(false, true, true);
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Update,
            new_run(&stored, CoreOperationKind::Update),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Failed);
        assert!(result.scan.is_none());
        let actions = executor.actions.lock().unwrap();
        assert!(actions.contains(&"UpdateCoreTo".into()));
        assert!(!actions.contains(&"UpdateDatabase".into()));
        assert!(!actions.contains(&"UpdateCoreLanguages".into()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ssh_disconnect_stops_before_backup_or_mutation() {
        let mut executor = mock(false, false, false);
        executor.auth_fails = true;
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Repair,
            new_run(&stored, CoreOperationKind::Repair),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Failed);
        let actions = executor.actions.lock().unwrap();
        assert!(!actions.contains(&"CreateDatabaseBackup".into()));
        assert!(!actions.contains(&"RepairCore".into()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn repair_leaves_unknown_files_as_checksum_findings() {
        let mut executor = mock(false, false, false);
        executor.checksum = r#"[{"file":"wp-admin/unknown.php","message":"File should not exist"}]
Success: WordPress installation verifies against checksums."#
            .into();
        let stored = stored();
        let root = std::env::temp_dir().join(format!("wpmm-core-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let result = execute_with_health(
            &executor,
            &stored,
            None,
            &root,
            CoreOperationKind::Repair,
            new_run(&stored, CoreOperationKind::Repair),
            |_| Ok(()),
            healthy,
        )
        .unwrap();
        assert_eq!(result.run.status, StepStatus::Warning);
        let checksum = result
            .scan
            .unwrap()
            .result
            .checks
            .into_iter()
            .find(|check| check.key == "core_checksum")
            .unwrap();
        assert_eq!(checksum.findings.len(), 1);
        assert_eq!(
            checksum.findings[0].checksum_status,
            Some(crate::models::ChecksumStatus::Unexpected)
        );
        assert!(
            !executor
                .actions
                .lock()
                .unwrap()
                .iter()
                .any(|action| { action.contains("Delete") && action != "DeleteTemporaryBackup" })
        );
        let _ = fs::remove_dir_all(root);
    }
}
