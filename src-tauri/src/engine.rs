use crate::{
    command_catalog::{RemoteAction, RemoteCommand, build},
    database::utc_now,
    error::AppError,
    models::{
        ChecksumStatus, Finding, FindingSeverity, ScanCheck, ScanResult, SiteStatus, StepStatus,
        StoredSite, UpdateItem, UpdateKind,
    },
    parsers,
    ssh::{ExecOutput, SshExecutor},
};
use uuid::Uuid;

pub struct ScanOutcome {
    pub result: ScanResult,
    pub security_status: String,
    pub wordpress_version: String,
    pub php_version: String,
}

pub fn scan_site(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    modified_days: u16,
) -> Result<ScanOutcome, AppError> {
    executor.authenticate(&stored.site, credential)?;
    let started_at = utc_now();
    let wordpress_version = text_action(
        executor,
        stored,
        credential,
        RemoteAction::GetWordPressVersion,
    )?
    .trim()
    .to_owned();
    let php_version = text_action(executor, stored, credential, RemoteAction::GetPhpVersion)?
        .trim()
        .to_owned();
    let mut truncated = false;
    let mut checks = Vec::new();

    checks.push(checksum_check(executor, stored, credential));
    checks.push(
        match text_action(executor, stored, credential, RemoteAction::ListUsers) {
            Ok(output) => match parsers::parse_users(&output) {
                Ok(findings) => {
                    findings_check("users", "Gebruikersaccounts", findings, "accounts", false)
                }
                Err(error) => failed_check("users", "Gebruikersaccounts", error),
            },
            Err(error) => failed_check("users", "Gebruikersaccounts", error),
        },
    );

    checks.push(
        match binary_action(executor, stored, credential, RemoteAction::FindPhpFiles) {
            Ok(output) => {
                let (findings, cut) =
                    parsers::parse_nul_paths(&output, &stored.site.wordpress_path, false);
                truncated |= cut;
                findings_check(
                    "php_files",
                    "PHP in wp-content",
                    findings,
                    "PHP-bestanden",
                    cut,
                )
            }
            Err(error) => failed_check("php_files", "PHP in wp-content", error),
        },
    );

    checks.push(
        match binary_action(executor, stored, credential, RemoteAction::FindPhpInUploads) {
            Ok(output) => {
                let (findings, cut) =
                    parsers::parse_nul_paths(&output, &stored.site.wordpress_path, true);
                truncated |= cut;
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
    );

    checks.push(
        match binary_action(
            executor,
            stored,
            credential,
            RemoteAction::FindModifiedFiles {
                days: modified_days,
            },
        ) {
            Ok(output) => {
                let (findings, cut) =
                    parsers::parse_modified_files(&output, &stored.site.wordpress_path);
                truncated |= cut;
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
    );

    checks.push(
        match binary_action(
            executor,
            stored,
            credential,
            RemoteAction::CheckUnsafePermissions,
        ) {
            Ok(output) => {
                let (findings, cut) =
                    parsers::permission_findings(&output, &stored.site.wordpress_path);
                truncated |= cut;
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
    );

    checks.push(
        match text_action(
            executor,
            stored,
            credential,
            RemoteAction::CheckSelectedWpConfigConstants,
        ) {
            Ok(output) => match parsers::parse_config(&output) {
                Ok(findings) => findings_check(
                    "configuration",
                    "WordPress-configuratie",
                    findings,
                    "instellingen",
                    false,
                ),
                Err(error) => failed_check("configuration", "WordPress-configuratie", error),
            },
            Err(error) => failed_check("configuration", "WordPress-configuratie", error),
        },
    );

    checks.push(
        match text_action(executor, stored, credential, RemoteAction::CheckDatabase) {
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
    );

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
        wordpress_version,
        php_version,
    })
}

pub fn check_updates(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
) -> Result<Vec<UpdateItem>, AppError> {
    executor.authenticate(&stored.site, credential)?;
    let current = text_action(
        executor,
        stored,
        credential,
        RemoteAction::GetWordPressVersion,
    )?;
    let mut updates = parsers::parse_core_updates(
        &text_action(executor, stored, credential, RemoteAction::CheckCoreUpdates)?,
        current.trim(),
    )?;
    updates.extend(parsers::parse_update_list(
        &text_action(
            executor,
            stored,
            credential,
            RemoteAction::ListPluginUpdates,
        )?,
        UpdateKind::Plugin,
    )?);
    updates.extend(parsers::parse_update_list(
        &text_action(executor, stored, credential, RemoteAction::ListThemeUpdates)?,
        UpdateKind::Theme,
    )?);
    Ok(updates)
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

fn binary_action(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    action: RemoteAction,
) -> Result<Vec<u8>, AppError> {
    Ok(checked_output(
        executor,
        &stored.site,
        credential,
        build(&stored.site.wordpress_path, action)?,
    )?
    .stdout)
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
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
) -> ScanCheck {
    let observed_at = utc_now();
    let command = match build(
        &stored.site.wordpress_path,
        RemoteAction::VerifyCoreChecksums,
    ) {
        Ok(command) => command,
        Err(error) => return failed_checksum_check(error, &observed_at),
    };
    match executor.execute(&stored.site, credential, &command) {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match parsers::parse_checksum_output(&stdout, &observed_at) {
                Ok(findings) if output.exit_code == 0 || !findings.is_empty() => {
                    checksum_findings_check(findings)
                }
                Ok(_) | Err(_) => {
                    checksum_plain_fallback(executor, stored, credential, &observed_at)
                }
            }
        }
        Err(error) => failed_checksum_check(error, &observed_at),
    }
}

fn checksum_plain_fallback(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    observed_at: &str,
) -> ScanCheck {
    let command = match build(
        &stored.site.wordpress_path,
        RemoteAction::VerifyCoreChecksumsPlain,
    ) {
        Ok(command) => command,
        Err(error) => return failed_checksum_check(error, observed_at),
    };
    let output = match executor.execute(&stored.site, credential, &command) {
        Ok(output) => output,
        Err(error) => return failed_checksum_check(error, observed_at),
    };
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    match parsers::parse_checksum_plain_output(&combined, observed_at) {
        Ok(findings) if output.exit_code == 0 || !findings.is_empty() => {
            checksum_findings_check(findings)
        }
        Ok(_) => failed_checksum_check(
            AppError::command_failed(command.action_name, output.exit_code, &combined),
            observed_at,
        ),
        Err(error) => failed_checksum_check(error, observed_at),
    }
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
    use std::collections::HashMap;

    struct MockSsh {
        outputs: HashMap<&'static str, ExecOutput>,
    }
    impl SshExecutor for MockSsh {
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
            ]),
        };

        let check = checksum_check(&ssh, &stored(), Some("secret"));
        assert_eq!(check.status, StepStatus::Warning);
        assert_eq!(check.findings.len(), 1);
        assert_eq!(
            check.findings[0].checksum_status,
            Some(ChecksumStatus::Unexpected)
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
        };
        let updates = check_updates(&ssh, &stored(), Some("secret")).unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[1].slug, "seo");
    }

    #[test]
    fn arbitrary_update_kinds_are_rejected() {
        let ssh = MockSsh {
            outputs: HashMap::new(),
        };
        let error = run_update(&ssh, &stored(), None, "shell", Some("id")).unwrap_err();
        assert_eq!(error.category, "validation");
    }
}
