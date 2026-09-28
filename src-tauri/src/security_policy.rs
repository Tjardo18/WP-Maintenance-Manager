use crate::{
    error::AppError,
    models::{
        ChecksumStatus, Finding, FindingDisposition, FindingException, FindingSeverity, ScanCheck,
        SiteStatus, StepStatus, TrustedFile, TrustedFileStatus,
    },
    validation::validate_checksum_relative_path,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub fn normalize_relative_path(path: &str) -> Result<String, AppError> {
    let normalized = path.replace('\\', "/");
    let normalized = normalized.trim_start_matches("./");
    validate_checksum_relative_path(normalized)?;
    Ok(normalized.to_owned())
}

pub fn finding_type(finding: &Finding) -> String {
    finding
        .checksum_status
        .map(ChecksumStatus::as_db)
        .unwrap_or(finding.category.as_str())
        .to_owned()
}

pub fn finding_target(finding: &Finding) -> Result<String, AppError> {
    if let Some(target) = finding.policy_target.as_deref() {
        if target.is_empty() || target.len() > 2_000 || target.chars().any(char::is_control) {
            return Err(AppError::validation("Ongeldige finding-identiteit."));
        }
        return Ok(target.to_owned());
    }
    finding
        .path
        .as_deref()
        .map_or_else(|| Ok(finding.category.clone()), normalize_relative_path)
}

pub fn apply_scan_policy(
    scan_site_id: &str,
    checks: &mut Vec<ScanCheck>,
    exceptions: &[FindingException],
    trusted_files: &[TrustedFile],
    now: DateTime<Utc>,
) -> String {
    let mut matched_trust_paths = Vec::new();
    for check in checks.iter_mut() {
        let had_findings = !check.findings.is_empty();
        for finding in &mut check.findings {
            finding.policy_reason = None;
            apply_default_severity(&check.key, finding);
            finding.disposition = FindingDisposition::Active;
            finding.exception_id = None;
            finding.trusted_file_id = None;

            let target = finding_target(finding).ok();
            let kind = finding_type(finding);
            if let Some(target) = target.as_deref()
                && let Some(exception) = exceptions.iter().find(|exception| {
                    exception.active
                        && exception.site_id == scan_site_id
                        && exception.check_type == check.key
                        && exception.finding_type == kind
                        && exception.target == target
                })
            {
                finding.exception_id = Some(exception.id.clone());
                if exception_is_expired(exception, now) {
                    finding.disposition = FindingDisposition::ExpiredException;
                    finding.policy_reason = Some("De tijdelijke uitzondering is verlopen.".into());
                } else {
                    finding.disposition = FindingDisposition::Ignored;
                    finding.policy_reason = Some("Deze specifieke melding is genegeerd.".into());
                }
            }

            if let Some(path) = finding
                .path
                .as_deref()
                .and_then(|path| normalize_relative_path(path).ok())
                && let Some(trusted) = trusted_files.iter().find(|trusted| {
                    trusted.active
                        && trusted.site_id == scan_site_id
                        && trusted.relative_path == path
                })
            {
                matched_trust_paths.push(path);
                finding.trusted_file_id = Some(trusted.id.clone());
                match trusted.status {
                    TrustedFileStatus::Trusted => {
                        finding.disposition = FindingDisposition::Trusted;
                        finding.policy_reason = Some(
                            "De huidige SHA-256-fingerprint komt overeen met de vertrouwde versie."
                                .into(),
                        );
                    }
                    TrustedFileStatus::Changed => {
                        finding.disposition = FindingDisposition::TrustedChanged;
                        finding.policy_reason = Some(
                            "Het bestand is gewijzigd sinds het expliciet werd vertrouwd.".into(),
                        );
                    }
                    TrustedFileStatus::Missing => {
                        finding.disposition = FindingDisposition::TrustedMissing;
                        finding.severity = FindingSeverity::Info;
                        finding.policy_reason =
                            Some("Het vertrouwde bestand bestaat niet meer.".into());
                    }
                    TrustedFileStatus::Unchecked => {}
                }
            }
        }
        if had_findings && check.status != StepStatus::Failed {
            check.status = if check.findings.iter().any(is_active_attention) {
                StepStatus::Warning
            } else {
                StepStatus::Success
            };
        }
    }

    let mut trust_findings = Vec::new();
    for trusted in trusted_files.iter().filter(|trusted| trusted.active) {
        if matched_trust_paths
            .iter()
            .any(|path| path == &trusted.relative_path)
        {
            continue;
        }
        let (severity, disposition, title, detail) = match trusted.status {
            TrustedFileStatus::Changed => (
                FindingSeverity::Warning,
                FindingDisposition::TrustedChanged,
                "Vertrouwd bestand is gewijzigd",
                "De huidige SHA-256-fingerprint wijkt af van de expliciet vertrouwde versie.",
            ),
            TrustedFileStatus::Missing => (
                FindingSeverity::Info,
                FindingDisposition::TrustedMissing,
                "Vertrouwd bestand bestaat niet meer",
                "De trustregistratie blijft bewaard, maar het bestand is niet meer aanwezig.",
            ),
            _ => continue,
        };
        trust_findings.push(Finding {
            id: Some(Uuid::new_v4().to_string()),
            category: "trusted-file".into(),
            severity,
            title: title.into(),
            detail: detail.into(),
            path: Some(trusted.relative_path.clone()),
            checksum_status: None,
            observed_at: trusted.last_checked_at.clone(),
            disposition,
            exception_id: None,
            trusted_file_id: Some(trusted.id.clone()),
            policy_reason: Some(detail.into()),
            policy_target: None,
            vulnerability: None,
        });
    }
    if !trust_findings.is_empty() {
        let changed = trust_findings
            .iter()
            .filter(|finding| finding.disposition == FindingDisposition::TrustedChanged)
            .count();
        let missing = trust_findings.len() - changed;
        checks.push(ScanCheck {
            key: "trusted_files".into(),
            label: "Vertrouwde bestanden".into(),
            status: if changed > 0 {
                StepStatus::Warning
            } else {
                StepStatus::Success
            },
            summary: format!("Gewijzigd: {changed} · Niet meer aanwezig: {missing}"),
            technical_details: None,
            findings: trust_findings,
        });
    }

    security_summary(checks)
}

pub fn calculate_site_status(checks: &[ScanCheck]) -> SiteStatus {
    if checks
        .iter()
        .flat_map(|check| &check.findings)
        .any(|finding| {
            finding.disposition.counts_as_active()
                && matches!(
                    finding.severity,
                    FindingSeverity::Critical | FindingSeverity::Problem
                )
        })
    {
        SiteStatus::Problem
    } else if checks.iter().any(|check| {
        (check.status == StepStatus::Failed
            && (check.findings.is_empty()
                || check
                    .findings
                    .iter()
                    .any(|finding| finding.disposition.counts_as_active())))
            || check.findings.iter().any(is_active_attention)
    }) {
        SiteStatus::Attention
    } else {
        SiteStatus::Healthy
    }
}

pub fn security_summary(checks: &[ScanCheck]) -> String {
    let findings: Vec<&Finding> = checks.iter().flat_map(|check| &check.findings).collect();
    let ignored = findings
        .iter()
        .filter(|finding| finding.disposition == FindingDisposition::Ignored)
        .count();
    let trusted = findings
        .iter()
        .filter(|finding| finding.disposition == FindingDisposition::Trusted)
        .count();
    let base = match calculate_site_status(checks) {
        SiteStatus::Problem => "Probleem gevonden",
        SiteStatus::Attention => {
            if checks
                .iter()
                .any(|check| check.status == StepStatus::Failed)
            {
                "Scan deels mislukt"
            } else {
                "Aandacht nodig"
            }
        }
        _ => "Geen actieve aandachtspunten",
    };
    match (ignored, trusted) {
        (0, 0) => base.into(),
        (ignored, 0) => format!("{base} · {ignored} genegeerd"),
        (0, trusted) => format!("{base} · {trusted} vertrouwd"),
        (ignored, trusted) => format!("{base} · {ignored} genegeerd · {trusted} vertrouwd"),
    }
}

fn apply_default_severity(check_type: &str, finding: &mut Finding) {
    if check_type == "modified_files" {
        // Recency is inventory metadata, not a security signal. Suspicious PHP content and
        // locations are reported by the dedicated PHP checks. An explicitly trusted file whose
        // hash changed can still become TrustedChanged later in the policy flow.
        finding.severity = FindingSeverity::Info;
        return;
    }
    let path = finding
        .path
        .as_deref()
        .and_then(|path| normalize_relative_path(path).ok());
    if check_type == "core_checksum" && finding.checksum_status == Some(ChecksumStatus::Missing) {
        if matches!(path.as_deref(), Some("readme.html" | "license.txt")) {
            finding.severity = FindingSeverity::Info;
            finding.policy_reason =
                Some("Een ontbrekend niet-uitvoerbaar distributiebestand is informatief.".into());
            return;
        }
        finding.severity = FindingSeverity::Warning;
    } else if check_type == "core_checksum"
        && finding.checksum_status == Some(ChecksumStatus::Modified)
    {
        finding.severity = FindingSeverity::Critical;
    } else if check_type == "core_checksum"
        && finding.checksum_status == Some(ChecksumStatus::Unexpected)
    {
        finding.severity = if path.as_deref().is_some_and(|path| path.ends_with(".php")) {
            FindingSeverity::Warning
        } else {
            FindingSeverity::Attention
        };
    } else if check_type == "php_uploads" || check_type == "permissions" {
        finding.severity = FindingSeverity::Warning;
    } else if path
        .as_deref()
        .is_some_and(|path| matches!(path, "wp-config.php" | ".htaccess"))
    {
        finding.severity = FindingSeverity::Critical;
    }
}

fn exception_is_expired(exception: &FindingException, now: DateTime<Utc>) -> bool {
    exception
        .expires_at
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|expires| expires <= now)
}

fn is_active_attention(finding: &Finding) -> bool {
    finding.disposition == FindingDisposition::TrustedChanged
        || (finding.disposition.counts_as_active() && finding.severity != FindingSeverity::Info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ExceptionScope;
    use chrono::Duration;

    fn finding(path: &str, status: ChecksumStatus) -> Finding {
        Finding {
            id: Some(Uuid::new_v4().to_string()),
            category: "wordpress-core".into(),
            severity: FindingSeverity::Problem,
            title: "Afwijking".into(),
            detail: "Test".into(),
            path: Some(path.into()),
            checksum_status: Some(status),
            observed_at: None,
            disposition: FindingDisposition::Active,
            exception_id: None,
            trusted_file_id: None,
            policy_reason: None,
            policy_target: None,
            vulnerability: None,
        }
    }

    fn exception(
        site_id: &str,
        target: &str,
        finding_type: &str,
        expires_at: Option<String>,
    ) -> FindingException {
        FindingException {
            id: Uuid::new_v4().to_string(),
            site_id: site_id.into(),
            site_name: "Test".into(),
            check_type: "core_checksum".into(),
            finding_type: finding_type.into(),
            target: target.into(),
            scope: ExceptionScope::Site,
            reason: "Handmatig genegeerd".into(),
            note: None,
            created_at: Utc::now().to_rfc3339(),
            expires_at,
            active: true,
        }
    }

    fn check(findings: Vec<Finding>) -> Vec<ScanCheck> {
        vec![ScanCheck {
            key: "core_checksum".into(),
            label: "Core".into(),
            status: StepStatus::Warning,
            summary: "Test".into(),
            technical_details: None,
            findings,
        }]
    }

    #[test]
    fn exception_matching_is_exact_by_site_check_type_finding_type_and_target() {
        let now = Utc::now();
        let ignored = exception("site-a", "readme.html", "missing", None);
        let mut checks = check(vec![
            finding("readme.html", ChecksumStatus::Missing),
            finding("readme.html", ChecksumStatus::Modified),
            finding("license.txt", ChecksumStatus::Missing),
        ]);
        apply_scan_policy(
            "site-a",
            &mut checks,
            std::slice::from_ref(&ignored),
            &[],
            now,
        );
        assert_eq!(
            checks[0].findings[0].disposition,
            FindingDisposition::Ignored
        );
        assert_eq!(
            checks[0].findings[1].disposition,
            FindingDisposition::Active
        );
        assert_eq!(
            checks[0].findings[2].disposition,
            FindingDisposition::Active
        );

        let mut other_site = check(vec![finding("readme.html", ChecksumStatus::Missing)]);
        apply_scan_policy("site-b", &mut other_site, &[ignored], &[], now);
        assert_eq!(
            other_site[0].findings[0].disposition,
            FindingDisposition::Active
        );
    }

    #[test]
    fn temporary_exception_suppresses_until_expiration_and_then_reactivates_the_finding() {
        let now = Utc::now();
        let mut temporary = exception(
            "site-a",
            "wp-settings.php",
            "modified",
            Some((now + Duration::minutes(1)).to_rfc3339()),
        );
        let raw = finding("wp-settings.php", ChecksumStatus::Modified);
        let mut checks = check(vec![raw.clone()]);
        apply_scan_policy(
            "site-a",
            &mut checks,
            std::slice::from_ref(&temporary),
            &[],
            now,
        );
        assert_eq!(
            checks[0].findings[0].disposition,
            FindingDisposition::Ignored
        );
        assert_eq!(checks[0].status, StepStatus::Success);
        assert_eq!(calculate_site_status(&checks), SiteStatus::Healthy);

        temporary.expires_at = Some((now - Duration::minutes(1)).to_rfc3339());
        let mut checks = check(vec![raw]);
        apply_scan_policy("site-a", &mut checks, &[temporary], &[], now);
        assert_eq!(
            checks[0].findings[0].disposition,
            FindingDisposition::ExpiredException
        );
        assert_eq!(checks[0].status, StepStatus::Warning);
        assert_eq!(calculate_site_status(&checks), SiteStatus::Problem);
        assert_eq!(
            checks[0].findings[0].policy_reason.as_deref(),
            Some("De tijdelijke uitzondering is verlopen.")
        );
    }

    #[test]
    fn vulnerability_exception_identity_includes_the_installed_version() {
        let now = Utc::now();
        let mut vulnerable = finding("unused", ChecksumStatus::Unexpected);
        vulnerable.category = "vulnerability".into();
        vulnerable.checksum_status = None;
        vulnerable.path = None;
        vulnerable.policy_target = Some("wordfence:vulnerability-a:plugin:example:1.2.3".into());
        let mut ignored = exception(
            "site-a",
            "wordfence:vulnerability-a:plugin:example:1.2.3",
            "vulnerability",
            None,
        );
        ignored.check_type = "vulnerabilities".into();
        let make_checks = |finding: Finding| {
            vec![ScanCheck {
                key: "vulnerabilities".into(),
                label: "Kwetsbaarheden".into(),
                status: StepStatus::Warning,
                summary: "Test".into(),
                technical_details: None,
                findings: vec![finding],
            }]
        };
        let mut same_version = make_checks(vulnerable.clone());
        apply_scan_policy(
            "site-a",
            &mut same_version,
            std::slice::from_ref(&ignored),
            &[],
            now,
        );
        assert_eq!(
            same_version[0].findings[0].disposition,
            FindingDisposition::Ignored
        );

        vulnerable.policy_target = Some("wordfence:vulnerability-a:plugin:example:1.2.4".into());
        let mut new_version = make_checks(vulnerable);
        apply_scan_policy("site-a", &mut new_version, &[ignored], &[], now);
        assert_eq!(
            new_version[0].findings[0].disposition,
            FindingDisposition::Active
        );
    }

    #[test]
    fn informational_ignored_and_trusted_findings_do_not_degrade_site_status() {
        let mut info = finding("readme.html", ChecksumStatus::Missing);
        info.severity = FindingSeverity::Info;
        let mut ignored = finding("wp-settings.php", ChecksumStatus::Missing);
        ignored.disposition = FindingDisposition::Ignored;
        let mut trusted = finding("custom.php", ChecksumStatus::Unexpected);
        trusted.disposition = FindingDisposition::Trusted;
        assert_eq!(
            calculate_site_status(&check(vec![info, ignored, trusted])),
            SiteStatus::Healthy
        );

        let mut warning = finding("custom.php", ChecksumStatus::Unexpected);
        warning.severity = FindingSeverity::Warning;
        assert_eq!(
            calculate_site_status(&check(vec![warning])),
            SiteStatus::Attention
        );

        let mut critical = finding("wp-settings.php", ChecksumStatus::Modified);
        critical.severity = FindingSeverity::Critical;
        assert_eq!(
            calculate_site_status(&check(vec![critical])),
            SiteStatus::Problem
        );
    }

    #[test]
    fn recent_file_changes_are_informational_but_real_security_findings_remain_active() {
        let now = Utc::now();
        let mut recent_change = finding("wp-config.php", ChecksumStatus::Modified);
        recent_change.checksum_status = None;
        recent_change.category = "root".into();
        recent_change.severity = FindingSeverity::Critical;
        recent_change.title = "Recent gewijzigd bestand vraagt aandacht".into();
        let mut checks = vec![ScanCheck {
            key: "modified_files".into(),
            label: "Gewijzigde bestanden".into(),
            status: StepStatus::Warning,
            summary: "1 gewijzigd bestand".into(),
            technical_details: None,
            findings: vec![recent_change],
        }];

        apply_scan_policy("site-a", &mut checks, &[], &[], now);

        assert_eq!(checks[0].status, StepStatus::Success);
        assert_eq!(checks[0].findings[0].severity, FindingSeverity::Info);
        assert_eq!(calculate_site_status(&checks), SiteStatus::Healthy);

        let mut suspicious_php =
            finding("wp-content/uploads/shell.php", ChecksumStatus::Unexpected);
        suspicious_php.checksum_status = None;
        suspicious_php.category = "uploads".into();
        suspicious_php.severity = FindingSeverity::Attention;
        checks.push(ScanCheck {
            key: "php_files".into(),
            label: "PHP in wp-content".into(),
            status: StepStatus::Warning,
            summary: "1 opvallend bestand".into(),
            technical_details: None,
            findings: vec![suspicious_php],
        });

        assert_eq!(calculate_site_status(&checks), SiteStatus::Attention);
    }

    #[test]
    fn hash_based_trust_reactivates_changed_files_and_retains_missing_records() {
        let now = Utc::now();
        let mut trusted = TrustedFile {
            id: Uuid::new_v4().to_string(),
            site_id: "site-a".into(),
            site_name: "Test".into(),
            relative_path: "wp-content/custom-loader.php".into(),
            trusted_sha256: "aaa".into(),
            current_sha256: Some("aaa".into()),
            size_bytes: 10,
            current_size_bytes: Some(10),
            modified_at_snapshot: None,
            current_modified_at: None,
            file_type: "regular".into(),
            status: TrustedFileStatus::Trusted,
            trusted_at: now.to_rfc3339(),
            last_checked_at: Some(now.to_rfc3339()),
            note: None,
            active: true,
        };
        let raw = finding("wp-content/custom-loader.php", ChecksumStatus::Unexpected);
        let mut checks = check(vec![raw.clone()]);
        apply_scan_policy("site-a", &mut checks, &[], &[trusted.clone()], now);
        assert_eq!(
            checks[0].findings[0].disposition,
            FindingDisposition::Trusted
        );
        assert_eq!(calculate_site_status(&checks), SiteStatus::Healthy);

        trusted.current_sha256 = Some("bbb".into());
        trusted.status = TrustedFileStatus::Changed;
        let mut checks = check(vec![raw.clone()]);
        apply_scan_policy("site-a", &mut checks, &[], &[trusted.clone()], now);
        assert_eq!(
            checks[0].findings[0].disposition,
            FindingDisposition::TrustedChanged
        );
        assert_eq!(calculate_site_status(&checks), SiteStatus::Attention);

        trusted.status = TrustedFileStatus::Missing;
        let mut checks = check(Vec::new());
        apply_scan_policy("site-a", &mut checks, &[], &[trusted.clone()], now);
        assert_eq!(
            checks[1].findings[0].disposition,
            FindingDisposition::TrustedMissing
        );
        assert_eq!(calculate_site_status(&checks), SiteStatus::Healthy);

        trusted.active = false;
        let mut checks = check(vec![raw]);
        apply_scan_policy("site-a", &mut checks, &[], &[trusted], now);
        assert_eq!(
            checks[0].findings[0].disposition,
            FindingDisposition::Active
        );
    }

    #[test]
    fn missing_distribution_files_are_info_but_modified_files_remain_critical() {
        let now = Utc::now();
        let mut checks = check(vec![
            finding("readme.html", ChecksumStatus::Missing),
            finding("license.txt", ChecksumStatus::Missing),
            finding("wp-settings.php", ChecksumStatus::Missing),
            finding("readme.html", ChecksumStatus::Modified),
        ]);
        apply_scan_policy("site-a", &mut checks, &[], &[], now);
        assert_eq!(checks[0].findings[0].severity, FindingSeverity::Info);
        assert_eq!(checks[0].findings[1].severity, FindingSeverity::Info);
        assert_eq!(checks[0].findings[2].severity, FindingSeverity::Warning);
        assert_eq!(checks[0].findings[3].severity, FindingSeverity::Critical);
    }

    #[test]
    fn normalizes_dot_prefix_but_rejects_traversal_and_preserves_case() {
        assert_eq!(
            normalize_relative_path("./readme.html").unwrap(),
            "readme.html"
        );
        assert_eq!(
            normalize_relative_path("Readme.html").unwrap(),
            "Readme.html"
        );
        assert!(normalize_relative_path("../../etc/passwd").is_err());
        assert!(normalize_relative_path("/etc/passwd").is_err());
    }
}
