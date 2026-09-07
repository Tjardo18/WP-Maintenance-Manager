use crate::{
    backup::{BackupResult, create_database_backup},
    database::utc_now,
    engine::{self, ScanOutcome},
    error::AppError,
    health::{HealthCheck, check_homepage},
    models::{
        MaintenanceRun, MaintenanceStep, SiteStatus, StepStatus, StoredSite, UpdateItem, UpdateKind,
    },
    ssh::SshExecutor,
};
use std::{path::Path, time::Instant};
use uuid::Uuid;

pub struct MaintenanceOutcome {
    pub run: MaintenanceRun,
    pub backup: Option<BackupResult>,
    pub scans: Vec<ScanOutcome>,
    pub updates_after: Vec<UpdateItem>,
}

struct UpdateStepRequest<'a> {
    key: &'a str,
    should_run: bool,
    update_kind: &'a str,
    skipped_detail: String,
}

pub fn new_run(stored: &StoredSite) -> MaintenanceRun {
    let steps = [
        ("preflight", "Preflight"),
        ("precheck", "Voorcontrole"),
        ("backup", "Databasebackup"),
        ("core", "WordPress bijwerken"),
        ("plugins", "Plugins bijwerken"),
        ("themes", "Thema's bijwerken"),
        ("languages", "Vertalingen bijwerken"),
        ("database", "WordPress database bijwerken"),
        ("postcheck", "Nacontrole"),
        ("homepage", "Homepage bereikbaar"),
    ]
    .into_iter()
    .map(|(key, label)| MaintenanceStep {
        key: key.into(),
        label: label.into(),
        status: StepStatus::Pending,
        detail: None,
    })
    .collect();
    MaintenanceRun {
        id: Uuid::new_v4().to_string(),
        site_id: stored.site.id.clone(),
        site_name: Some(stored.site.name.clone()),
        started_at: utc_now(),
        finished_at: None,
        status: StepStatus::Running,
        duration_ms: None,
        backup_path: None,
        steps,
        before_versions: None,
        after_versions: None,
    }
}

pub fn execute<F>(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    backup_root: &Path,
    mut run: MaintenanceRun,
    mut progress: F,
) -> Result<MaintenanceOutcome, AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
{
    let timer = Instant::now();
    let mut scans = Vec::new();
    let mut backup = None;

    set_step(
        &mut run,
        "preflight",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    let preflight = (|| {
        executor.authenticate(&stored.site, credential)?;
        engine::text_action(
            executor,
            stored,
            credential,
            crate::command_catalog::RemoteAction::DetectWordPress,
        )?;
        let version = engine::text_action(
            executor,
            stored,
            credential,
            crate::command_catalog::RemoteAction::GetWordPressVersion,
        )?;
        engine::text_action(
            executor,
            stored,
            credential,
            crate::command_catalog::RemoteAction::CheckDatabase,
        )?;
        let updates = engine::check_updates(executor, stored, credential)?;
        Ok::<_, AppError>((version.trim().to_owned(), updates))
    })();
    let (before_version, updates_before) = match preflight {
        Ok(values) => values,
        Err(error) => {
            set_step(
                &mut run,
                "preflight",
                StepStatus::Failed,
                Some(error.user_message.clone()),
                &mut progress,
            )?;
            skip_remaining(&mut run, "preflight", &mut progress)?;
            finish(&mut run, StepStatus::Failed, timer);
            return Ok(MaintenanceOutcome {
                run,
                backup,
                scans,
                updates_after: Vec::new(),
            });
        }
    };
    run.before_versions = Some(version_summary(&before_version, &updates_before));
    set_step(
        &mut run,
        "preflight",
        StepStatus::Success,
        Some(format!(
            "WordPress {before_version}; {} beschikbare updates.",
            updates_before.len()
        )),
        &mut progress,
    )?;

    set_step(
        &mut run,
        "precheck",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    match engine::scan_site(executor, stored, credential, 30) {
        Ok(scan) => {
            let status = match scan.result.status {
                SiteStatus::Healthy | SiteStatus::Updates => StepStatus::Success,
                _ => StepStatus::Warning,
            };
            let detail = scan.security_status.clone();
            scans.push(scan);
            set_step(&mut run, "precheck", status, Some(detail), &mut progress)?;
        }
        Err(error) => {
            set_step(
                &mut run,
                "precheck",
                StepStatus::Failed,
                Some(error.user_message),
                &mut progress,
            )?;
            skip_remaining(&mut run, "precheck", &mut progress)?;
            finish(&mut run, StepStatus::Failed, timer);
            return Ok(MaintenanceOutcome {
                run,
                backup,
                scans,
                updates_after: updates_before.clone(),
            });
        }
    }

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
            set_step(
                &mut run,
                "backup",
                StepStatus::Failed,
                Some(format!(
                    "Backup mislukt — onderhoud gestopt. {}",
                    error.user_message
                )),
                &mut progress,
            )?;
            skip_remaining(&mut run, "backup", &mut progress)?;
            finish(&mut run, StepStatus::Failed, timer);
            return Ok(MaintenanceOutcome {
                run,
                backup,
                scans,
                updates_after: updates_before.clone(),
            });
        }
    }

    let has_core = updates_before
        .iter()
        .any(|item| item.kind == UpdateKind::Core);
    let plugins = updates_before
        .iter()
        .filter(|item| item.kind == UpdateKind::Plugin)
        .count();
    let themes = updates_before
        .iter()
        .filter(|item| item.kind == UpdateKind::Theme)
        .count();
    run_update_step(
        executor,
        stored,
        credential,
        &mut run,
        UpdateStepRequest {
            key: "core",
            should_run: has_core,
            update_kind: "core",
            skipped_detail: format!("WordPress {before_version} was al actueel."),
        },
        &mut progress,
    )?;
    run_update_step(
        executor,
        stored,
        credential,
        &mut run,
        UpdateStepRequest {
            key: "plugins",
            should_run: plugins > 0,
            update_kind: "plugins",
            skipped_detail: "Geen pluginupdates beschikbaar.".into(),
        },
        &mut progress,
    )?;
    run_update_step(
        executor,
        stored,
        credential,
        &mut run,
        UpdateStepRequest {
            key: "themes",
            should_run: themes > 0,
            update_kind: "themes",
            skipped_detail: "Geen thema-updates beschikbaar.".into(),
        },
        &mut progress,
    )?;
    run_update_step(
        executor,
        stored,
        credential,
        &mut run,
        UpdateStepRequest {
            key: "languages",
            should_run: true,
            update_kind: "languages",
            skipped_detail: String::new(),
        },
        &mut progress,
    )?;
    run_update_step(
        executor,
        stored,
        credential,
        &mut run,
        UpdateStepRequest {
            key: "database",
            should_run: true,
            update_kind: "database",
            skipped_detail: String::new(),
        },
        &mut progress,
    )?;

    set_step(
        &mut run,
        "postcheck",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    match engine::scan_site(executor, stored, credential, 30) {
        Ok(scan) => {
            let status = match scan.result.status {
                SiteStatus::Healthy | SiteStatus::Updates => StepStatus::Success,
                _ => StepStatus::Warning,
            };
            let detail = format!(
                "{}; core en database opnieuw gecontroleerd.",
                scan.security_status
            );
            scans.push(scan);
            set_step(&mut run, "postcheck", status, Some(detail), &mut progress)?;
        }
        Err(error) => set_step(
            &mut run,
            "postcheck",
            StepStatus::Failed,
            Some(error.user_message),
            &mut progress,
        )?,
    }

    set_step(
        &mut run,
        "homepage",
        StepStatus::Running,
        None,
        &mut progress,
    )?;
    let health = check_homepage(&stored.site.url)?;
    set_health_step(&mut run, &health, &mut progress)?;

    let updates_after = match engine::check_updates(executor, stored, credential) {
        Ok(updates) => updates,
        Err(error) => {
            set_step(
                &mut run,
                "postcheck",
                StepStatus::Warning,
                Some(format!(
                    "De update-status kon na afloop niet worden opgehaald: {}",
                    error.user_message
                )),
                &mut progress,
            )?;
            updates_before.clone()
        }
    };
    let after_version = match engine::text_action(
        executor,
        stored,
        credential,
        crate::command_catalog::RemoteAction::GetWordPressVersion,
    ) {
        Ok(version) => version,
        Err(error) => {
            set_step(
                &mut run,
                "postcheck",
                StepStatus::Warning,
                Some(format!(
                    "De WordPress-versie kon na afloop niet opnieuw worden gelezen: {}",
                    error.user_message
                )),
                &mut progress,
            )?;
            before_version.clone()
        }
    };
    run.after_versions = Some(version_summary(after_version.trim(), &updates_after));
    let final_status = if run
        .steps
        .iter()
        .any(|step| matches!(step.status, StepStatus::Failed | StepStatus::Warning))
    {
        StepStatus::Warning
    } else {
        StepStatus::Success
    };
    finish(&mut run, final_status, timer);
    Ok(MaintenanceOutcome {
        run,
        backup,
        scans,
        updates_after,
    })
}

fn run_update_step<F>(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    run: &mut MaintenanceRun,
    request: UpdateStepRequest<'_>,
    progress: &mut F,
) -> Result<(), AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
{
    if !request.should_run {
        return set_step(
            run,
            request.key,
            StepStatus::Skipped,
            Some(request.skipped_detail),
            progress,
        );
    }
    set_step(run, request.key, StepStatus::Running, None, progress)?;
    match engine::run_update(executor, stored, credential, request.update_kind, None) {
        Ok(()) => set_step(
            run,
            request.key,
            StepStatus::Success,
            Some("Bijwerken voltooid.".into()),
            progress,
        ),
        Err(error) => set_step(
            run,
            request.key,
            StepStatus::Failed,
            Some(error.user_message),
            progress,
        ),
    }
}

fn set_health_step<F>(
    run: &mut MaintenanceRun,
    health: &HealthCheck,
    progress: &mut F,
) -> Result<(), AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
{
    let successful_status = health
        .status_code
        .is_some_and(|status| (200..400).contains(&status));
    set_step(
        run,
        "homepage",
        if health.reachable && successful_status {
            StepStatus::Success
        } else {
            StepStatus::Warning
        },
        Some(format!(
            "{} Reactietijd circa {} ms.",
            health.detail, health.response_time_ms
        )),
        progress,
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
        .ok_or_else(|| AppError::validation("Onbekende onderhoudsstap."))?;
    step.status = status;
    step.detail = detail;
    progress(step)
}

fn skip_remaining<F>(
    run: &mut MaintenanceRun,
    failed_key: &str,
    progress: &mut F,
) -> Result<(), AppError>
where
    F: FnMut(&MaintenanceStep) -> Result<(), AppError>,
{
    let failed_position = run
        .steps
        .iter()
        .position(|step| step.key == failed_key)
        .unwrap_or(0);
    for step in run.steps.iter_mut().skip(failed_position + 1) {
        step.status = StepStatus::Skipped;
        step.detail = Some("Niet uitgevoerd omdat een kritieke eerdere stap mislukte.".into());
        progress(step)?;
    }
    Ok(())
}

fn finish(run: &mut MaintenanceRun, status: StepStatus, timer: Instant) {
    run.status = status;
    run.finished_at = Some(utc_now());
    run.duration_ms = Some(timer.elapsed().as_millis().min(u64::MAX as u128) as u64);
}

fn version_summary(wordpress: &str, updates: &[UpdateItem]) -> String {
    let plugins = updates
        .iter()
        .filter(|item| item.kind == UpdateKind::Plugin)
        .count();
    let themes = updates
        .iter()
        .filter(|item| item.kind == UpdateKind::Theme)
        .count();
    format!("WordPress {wordpress} · {plugins} pluginupdates · {themes} thema-updates")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command_catalog::RemoteCommand,
        models::{AuthMethod, Site},
        ssh::ExecOutput,
    };
    use std::{collections::HashMap, path::Path, sync::Mutex};

    struct BackupFailingSsh {
        outputs: HashMap<&'static str, ExecOutput>,
        actions: Mutex<Vec<String>>,
    }

    impl SshExecutor for BackupFailingSsh {
        fn fingerprint(&self, _: &Site) -> Result<String, AppError> {
            Ok("SHA256:test".into())
        }
        fn authenticate(&self, _: &Site, _: Option<&str>) -> Result<(), AppError> {
            Ok(())
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
            self.outputs
                .get(command.action_name)
                .cloned()
                .ok_or_else(|| {
                    AppError::validation(format!("Geen fixture voor {}", command.action_name))
                })
        }
        fn download(&self, _: &Site, _: Option<&str>, _: &str, _: &Path) -> Result<u64, AppError> {
            panic!("download mag na mislukte export niet starten")
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

    fn stored() -> StoredSite {
        StoredSite {
            site: Site {
                id: Uuid::new_v4().to_string(),
                name: "Test".into(),
                url: "https://example.test".into(),
                ssh_host: "example.test".into(),
                ssh_port: 22,
                ssh_username: "deploy".into(),
                auth_method: AuthMethod::Password,
                key_path: None,
                wordpress_path: "/var/www".into(),
                pinned_host_key: Some("SHA256:test".into()),
                status: SiteStatus::Unscanned,
                wordpress_version: None,
                php_version: None,
                update_count: 0,
                security_status: None,
                last_scan_at: None,
                last_maintenance_at: None,
                created_at: utc_now(),
                updated_at: utc_now(),
            },
            credential_ref: None,
        }
    }

    #[test]
    fn failed_backup_stops_before_any_update() {
        let mut outputs = HashMap::from([
            ("DetectWordPress", output("")),
            ("GetWordPressVersion", output("6.8.2")),
            ("GetPhpVersion", output("8.3.0")),
            ("CheckDatabase", output("Success")),
            ("CheckCoreUpdates", output("[]")),
            ("ListPluginUpdates", output("[]")),
            ("ListThemeUpdates", output("[]")),
            ("VerifyCoreChecksums", output("Success")),
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
        ]);
        outputs.insert(
            "CreateDatabaseBackup",
            ExecOutput {
                stdout: Vec::new(),
                stderr: b"export failed".to_vec(),
                exit_code: 1,
                truncated: false,
            },
        );
        let ssh = BackupFailingSsh {
            outputs,
            actions: Mutex::new(Vec::new()),
        };
        let root = std::env::temp_dir().join(format!("wpmm-maintenance-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let stored = stored();
        let outcome = execute(&ssh, &stored, None, &root, new_run(&stored), |_| Ok(())).unwrap();
        assert_eq!(outcome.run.status, StepStatus::Failed);
        assert_eq!(
            outcome
                .run
                .steps
                .iter()
                .find(|step| step.key == "backup")
                .unwrap()
                .status,
            StepStatus::Failed
        );
        assert!(
            !ssh.actions
                .lock()
                .unwrap()
                .iter()
                .any(|action| action.starts_with("Update"))
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
