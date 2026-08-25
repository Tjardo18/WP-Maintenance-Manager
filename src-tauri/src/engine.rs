use crate::{
    command_catalog::{RemoteAction, RemoteCommand, build},
    database::utc_now,
    error::AppError,
    models::{
        Finding, FindingSeverity, ScanCheck, ScanResult, SiteStatus, StepStatus, StoredSite,
        UpdateItem, UpdateKind,
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
    let command = match build(
        &stored.site.wordpress_path,
        RemoteAction::VerifyCoreChecksums,
    ) {
        Ok(command) => command,
        Err(error) => return failed_check("core_checksum", "WordPress core", error),
    };
    match executor.execute(&stored.site, credential, &command) {
        Ok(output) if output.exit_code == 0 => ScanCheck {
            key: "core_checksum".into(),
            label: "WordPress core".into(),
            status: StepStatus::Success,
            summary: "WordPress core: in orde.".into(),
            findings: Vec::new(),
        },
        Ok(output) => {
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let mut findings: Vec<Finding> = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .take(200)
                .map(|line| Finding {
                    category: "wordpress-core".into(),
                    severity: FindingSeverity::Problem,
                    title: "Core checksum wijkt af".into(),
                    detail: line.trim().to_owned(),
                    path: extract_checksum_path(line),
                })
                .collect();
            if findings.is_empty() {
                findings.push(Finding {
                    category: "wordpress-core".into(),
                    severity: FindingSeverity::Problem,
                    title: "Core checksumcontrole mislukt".into(),
                    detail: format!("WP-CLI exitstatus {}", output.exit_code),
                    path: None,
                });
            }
            ScanCheck {
                key: "core_checksum".into(),
                label: "WordPress core".into(),
                status: StepStatus::Warning,
                summary: format!("{} checksumafwijkingen gemeld.", findings.len()),
                findings,
            }
        }
        Err(error) => failed_check("core_checksum", "WordPress core", error),
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
        findings,
    }
}

fn failed_check(key: &str, label: &str, error: AppError) -> ScanCheck {
    ScanCheck {
        key: key.into(),
        label: label.into(),
        status: StepStatus::Failed,
        summary: error.user_message,
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

fn extract_checksum_path(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|part| part.contains('/') || part.ends_with(".php"))
        .map(|part| part.trim_matches([':', ',', '\'', '"']).to_owned())
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
        }
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
}
