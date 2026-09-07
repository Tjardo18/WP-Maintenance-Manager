use crate::{
    error::AppError,
    validation::{
        validate_days, validate_display_name, validate_email, validate_role, validate_slug,
        validate_user_id, validate_wordpress_locale, validate_wordpress_path,
        validate_wordpress_version,
    },
};
use std::time::Duration;

pub const MAX_SCAN_RESULTS: usize = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
// The allowlist is intentionally complete before every UI flow is activated.
#[allow(dead_code)]
pub enum RemoteAction {
    TestWordPressPath,
    DetectWordPress,
    GetWordPressVersion,
    GetPhpVersion,
    GetWpCliVersion,
    GetSiteUrl,
    GetCoreLocale,
    CheckDiskSpace,
    VerifyCoreChecksums,
    VerifyCoreChecksumsPlain,
    ListUsers,
    ListRoles,
    DetectMultisite,
    UpdateUser {
        user_id: u64,
        display_name: String,
        email: String,
        role: Option<String>,
    },
    DeleteUser {
        user_id: u64,
        reassign_to: Option<u64>,
    },
    FindPhpFiles,
    FindPhpInUploads,
    FindModifiedFiles {
        days: u16,
    },
    CheckUnsafePermissions,
    CheckSelectedWpConfigConstants,
    CheckCoreUpdates,
    ListPluginUpdates,
    ListThemeUpdates,
    CheckDatabase,
    DatabaseSizes,
    CreateDatabaseBackup,
    DeleteTemporaryBackup {
        path: String,
    },
    UpdateCore,
    UpdateCoreTo {
        version: String,
    },
    RepairCore {
        version: String,
        locale: String,
    },
    UpdatePlugin {
        slug: String,
    },
    UpdateAllPlugins,
    UpdateTheme {
        slug: String,
    },
    UpdateAllThemes,
    UpdateLanguages,
    UpdateCoreLanguages,
    UpdateDatabase,
}

#[derive(Debug, Clone)]
pub struct RemoteCommand {
    pub action_name: &'static str,
    pub command: String,
    pub mutating: bool,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub truncate_output: bool,
}

pub fn build(wordpress_path: &str, action: RemoteAction) -> Result<RemoteCommand, AppError> {
    validate_wordpress_path(wordpress_path)?;
    let path = shell_escape(wordpress_path);
    let wp = format!("LC_ALL=C wp --no-color --path={path}");
    let normal = Duration::from_secs(60);
    let scan = Duration::from_secs(120);
    let update = Duration::from_secs(600);
    let (name, body, mutating, timeout, max) = match action {
        RemoteAction::TestWordPressPath => (
            "TestWordPressPath",
            format!("test -d {path}"),
            false,
            Duration::from_secs(20),
            1024,
        ),
        RemoteAction::DetectWordPress => (
            "DetectWordPress",
            format!("{wp} core is-installed"),
            false,
            normal,
            16 * 1024,
        ),
        RemoteAction::GetWordPressVersion => (
            "GetWordPressVersion",
            format!("{wp} core version"),
            false,
            normal,
            16 * 1024,
        ),
        RemoteAction::GetPhpVersion => (
            "GetPhpVersion",
            "LC_ALL=C php -r 'echo PHP_VERSION;'".into(),
            false,
            Duration::from_secs(20),
            16 * 1024,
        ),
        RemoteAction::GetWpCliVersion => (
            "GetWpCliVersion",
            "LC_ALL=C wp --no-color cli version".into(),
            false,
            Duration::from_secs(20),
            16 * 1024,
        ),
        RemoteAction::GetSiteUrl => (
            "GetSiteUrl",
            format!("{wp} option get siteurl"),
            false,
            normal,
            16 * 1024,
        ),
        RemoteAction::GetCoreLocale => (
            "GetCoreLocale",
            format!("{wp} eval {}", shell_escape("echo determine_locale();")),
            false,
            normal,
            16 * 1024,
        ),
        RemoteAction::CheckDiskSpace => (
            "CheckDiskSpace",
            format!("df -Pk {path} | awk 'NR==2 {{print $4}}'"),
            false,
            normal,
            16 * 1024,
        ),
        RemoteAction::VerifyCoreChecksums => (
            "VerifyCoreChecksums",
            format!(
                "{wp} core is-installed && {wp} core verify-checksums --include-root --format=json"
            ),
            false,
            scan,
            512 * 1024,
        ),
        RemoteAction::VerifyCoreChecksumsPlain => (
            "VerifyCoreChecksumsPlain",
            format!("{wp} core is-installed && {wp} core verify-checksums --include-root"),
            false,
            scan,
            512 * 1024,
        ),
        RemoteAction::ListUsers => (
            "ListUsers",
            format!(
                "{wp} user list --fields=ID,user_login,display_name,user_email,roles,user_registered --format=json"
            ),
            false,
            normal,
            2 * 1024 * 1024,
        ),
        RemoteAction::ListRoles => (
            "ListRoles",
            format!("{wp} role list --fields=role,name --format=json"),
            false,
            normal,
            256 * 1024,
        ),
        RemoteAction::DetectMultisite => (
            "DetectMultisite",
            format!(
                "{wp} eval {}",
                shell_escape("echo is_multisite() ? '1' : '0';")
            ),
            false,
            normal,
            16 * 1024,
        ),
        RemoteAction::UpdateUser {
            user_id,
            display_name,
            email,
            role,
        } => {
            validate_user_id(user_id)?;
            validate_display_name(&display_name)?;
            validate_email(&email)?;
            if let Some(role) = role.as_deref() {
                validate_role(role)?;
            }
            let role_argument = role
                .as_deref()
                .map(|role| format!(" --role={}", shell_escape(role)))
                .unwrap_or_default();
            (
                "UpdateUser",
                format!(
                    "{wp} user update {user_id} --display_name={} --user_email={}{} --skip-email",
                    shell_escape(display_name.trim()),
                    shell_escape(email.trim()),
                    role_argument
                ),
                true,
                normal,
                64 * 1024,
            )
        }
        RemoteAction::DeleteUser {
            user_id,
            reassign_to,
        } => {
            validate_user_id(user_id)?;
            if let Some(target) = reassign_to {
                validate_user_id(target)?;
                if target == user_id {
                    return Err(AppError::validation(
                        "Content kan niet aan dezelfde gebruiker worden toegewezen.",
                    ));
                }
            }
            let reassign = reassign_to
                .map(|target| format!(" --reassign={target}"))
                .unwrap_or_default();
            (
                "DeleteUser",
                format!("{wp} user delete {user_id}{reassign} --yes"),
                true,
                normal,
                64 * 1024,
            )
        }
        RemoteAction::FindPhpFiles => (
            "FindPhpFiles",
            limit_nul_records(
                format!("find {path}/wp-content -type f -name '*.php' -print0"),
                MAX_SCAN_RESULTS + 1,
            ),
            false,
            scan,
            4 * 1024 * 1024,
        ),
        RemoteAction::FindPhpInUploads => (
            "FindPhpInUploads",
            limit_nul_records(
                format!("find {path}/wp-content/uploads -type f -name '*.php' -print0"),
                MAX_SCAN_RESULTS + 1,
            ),
            false,
            scan,
            4 * 1024 * 1024,
        ),
        RemoteAction::FindModifiedFiles { days } => {
            validate_days(days)?;
            (
                "FindModifiedFiles",
                limit_nul_records(
                    format!("find {path} -xdev -type f -mtime -{days} -printf '%p\\0%T@\\0%m\\0'"),
                    (MAX_SCAN_RESULTS + 1) * 3,
                ),
                false,
                scan,
                8 * 1024 * 1024,
            )
        }
        RemoteAction::CheckUnsafePermissions => (
            "CheckUnsafePermissions",
            limit_nul_records(
                format!("find {path} -xdev \\( -type f -o -type d \\) -perm -0002 -print0"),
                MAX_SCAN_RESULTS + 1,
            ),
            false,
            scan,
            4 * 1024 * 1024,
        ),
        RemoteAction::CheckSelectedWpConfigConstants => {
            let code = "echo json_encode(array('WP_DEBUG'=>defined('WP_DEBUG') ? (bool) WP_DEBUG : null,'DISALLOW_FILE_EDIT'=>defined('DISALLOW_FILE_EDIT') ? (bool) DISALLOW_FILE_EDIT : null,'WP_ENVIRONMENT_TYPE'=>function_exists('wp_get_environment_type') ? wp_get_environment_type() : (defined('WP_ENVIRONMENT_TYPE') ? WP_ENVIRONMENT_TYPE : 'production'),'WP_ENVIRONMENT_TYPE_EXPLICIT'=>defined('WP_ENVIRONMENT_TYPE') || (function_exists('getenv') && getenv('WP_ENVIRONMENT_TYPE') !== false)));";
            (
                "CheckSelectedWpConfigConstants",
                format!("{wp} eval {}", shell_escape(code)),
                false,
                normal,
                64 * 1024,
            )
        }
        RemoteAction::CheckCoreUpdates => (
            "CheckCoreUpdates",
            format!("{wp} core check-update --format=json"),
            false,
            normal,
            512 * 1024,
        ),
        RemoteAction::ListPluginUpdates => (
            "ListPluginUpdates",
            format!(
                "{wp} plugin list --update=available --fields=name,title,status,version,update_version --format=json"
            ),
            false,
            normal,
            2 * 1024 * 1024,
        ),
        RemoteAction::ListThemeUpdates => (
            "ListThemeUpdates",
            format!(
                "{wp} theme list --update=available --fields=name,title,status,version,update_version --format=json"
            ),
            false,
            normal,
            2 * 1024 * 1024,
        ),
        RemoteAction::CheckDatabase => (
            "CheckDatabase",
            format!("{wp} db check"),
            false,
            Duration::from_secs(180),
            2 * 1024 * 1024,
        ),
        RemoteAction::DatabaseSizes => (
            "DatabaseSizes",
            format!("{wp} db size --tables --format=json"),
            false,
            scan,
            2 * 1024 * 1024,
        ),
        RemoteAction::CreateDatabaseBackup => (
            "CreateDatabaseBackup",
            format!(
                "remote_file=$(mktemp /tmp/wpmm-XXXXXXXX.sql) || exit 1; if {wp} db export \"$remote_file\" --quiet; then printf '%s' \"$remote_file\"; else rm -f -- \"$remote_file\"; exit 1; fi"
            ),
            true,
            Duration::from_secs(600),
            4096,
        ),
        RemoteAction::DeleteTemporaryBackup { path: remote_path } => {
            validate_remote_backup_path(&remote_path)?;
            (
                "DeleteTemporaryBackup",
                format!("rm -f -- {}", shell_escape(&remote_path)),
                true,
                Duration::from_secs(30),
                4096,
            )
        }
        RemoteAction::UpdateCore => (
            "UpdateCore",
            format!("{wp} core update --format=json"),
            true,
            update,
            2 * 1024 * 1024,
        ),
        RemoteAction::UpdateCoreTo { version } => {
            validate_wordpress_version(&version)?;
            (
                "UpdateCoreTo",
                format!(
                    "{wp} core update --version={} --format=json",
                    shell_escape(&version)
                ),
                true,
                update,
                2 * 1024 * 1024,
            )
        }
        RemoteAction::RepairCore { version, locale } => {
            validate_wordpress_version(&version)?;
            validate_wordpress_locale(&locale)?;
            (
                "RepairCore",
                format!(
                    "{wp} core download --version={} --locale={} --force --skip-content",
                    shell_escape(&version),
                    shell_escape(&locale)
                ),
                true,
                update,
                2 * 1024 * 1024,
            )
        }
        RemoteAction::UpdatePlugin { slug } => {
            validate_slug(&slug)?;
            (
                "UpdatePlugin",
                format!("{wp} plugin update {} --format=json", shell_escape(&slug)),
                true,
                Duration::from_secs(300),
                2 * 1024 * 1024,
            )
        }
        RemoteAction::UpdateAllPlugins => (
            "UpdateAllPlugins",
            format!("{wp} plugin update --all --format=json"),
            true,
            Duration::from_secs(900),
            4 * 1024 * 1024,
        ),
        RemoteAction::UpdateTheme { slug } => {
            validate_slug(&slug)?;
            (
                "UpdateTheme",
                format!("{wp} theme update {} --format=json", shell_escape(&slug)),
                true,
                Duration::from_secs(300),
                2 * 1024 * 1024,
            )
        }
        RemoteAction::UpdateAllThemes => (
            "UpdateAllThemes",
            format!("{wp} theme update --all --format=json"),
            true,
            update,
            4 * 1024 * 1024,
        ),
        RemoteAction::UpdateLanguages => (
            "UpdateLanguages",
            format!(
                "{wp} language core update && {wp} language plugin update --all && {wp} language theme update --all"
            ),
            true,
            Duration::from_secs(300),
            2 * 1024 * 1024,
        ),
        RemoteAction::UpdateCoreLanguages => (
            "UpdateCoreLanguages",
            format!("{wp} language core update"),
            true,
            Duration::from_secs(300),
            2 * 1024 * 1024,
        ),
        RemoteAction::UpdateDatabase => (
            "UpdateDatabase",
            format!("{wp} core update-db"),
            true,
            Duration::from_secs(300),
            2 * 1024 * 1024,
        ),
    };
    Ok(RemoteCommand {
        action_name: name,
        command: body,
        mutating,
        timeout,
        max_output_bytes: max,
        truncate_output: false,
    })
}

pub fn shell_escape(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn limit_nul_records(command: String, limit: usize) -> String {
    let php = format!(
        "$limit={limit};$seen=0;while(!feof(STDIN)){{$chunk=fread(STDIN,65536);if($chunk===false){{exit(1);}}$offset=0;while(($position=strpos($chunk,\"\\0\",$offset))!==false){{$seen++;if($seen>=$limit){{echo substr($chunk,0,$position+1);exit(0);}}$offset=$position+1;}}echo $chunk;}}"
    );
    format!("{command} | LC_ALL=C php -r {}", shell_escape(&php))
}

pub fn validate_remote_backup_path(path: &str) -> Result<(), AppError> {
    let Some(name) = path.strip_prefix("/tmp/wpmm-") else {
        return Err(AppError::validation(
            "Het tijdelijke backuppad is ongeldig.",
        ));
    };
    let Some(token) = name.strip_suffix(".sql") else {
        return Err(AppError::validation(
            "Het tijdelijke backuppad is ongeldig.",
        ));
    };
    if token.len() != 8 || !token.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(AppError::validation(
            "Het tijdelijke backuppad is ongeldig.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_single_quotes_for_posix_shells() {
        assert_eq!(shell_escape("a'b"), "'a'\"'\"'b'");
        let command = build(
            "/srv/$(touch injected); site's root",
            RemoteAction::GetWordPressVersion,
        )
        .unwrap();
        assert!(
            command
                .command
                .contains("--path='/srv/$(touch injected); site'\"'\"'s root'")
        );
    }

    #[test]
    fn rejects_injected_slugs() {
        assert!(
            build(
                "/var/www",
                RemoteAction::UpdatePlugin {
                    slug: "seo; id".into()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn generated_update_contains_only_validated_slug() {
        let command = build(
            "/var/www/site",
            RemoteAction::UpdateTheme {
                slug: "twenty-twenty-six".into(),
            },
        )
        .unwrap();
        assert!(command.mutating);
        assert!(command.command.contains("'twenty-twenty-six'"));
    }

    #[test]
    fn bounds_file_scan_days() {
        assert!(build("/var/www", RemoteAction::FindModifiedFiles { days: 0 }).is_err());
        assert!(build("/var/www", RemoteAction::FindModifiedFiles { days: 30 }).is_ok());
    }

    #[test]
    fn file_scans_use_portable_php_nul_limiter() {
        for action in [
            RemoteAction::FindPhpFiles,
            RemoteAction::FindPhpInUploads,
            RemoteAction::FindModifiedFiles { days: 30 },
            RemoteAction::CheckUnsafePermissions,
        ] {
            let command = build("/srv/site", action).unwrap().command;
            assert!(!command.contains("head -z"));
            assert!(command.contains("php -r"));
            assert!(command.contains("strpos"));
        }
    }

    #[test]
    fn only_backend_temporary_backup_paths_can_be_deleted() {
        assert!(validate_remote_backup_path("/tmp/wpmm-Ab12Cd34.sql").is_ok());
        assert!(validate_remote_backup_path("/var/www/wp-config.php").is_err());
        assert!(validate_remote_backup_path("/tmp/wpmm-../../etc.sql").is_err());
    }

    #[test]
    fn checksum_command_is_root_scoped_and_structured() {
        let command = build("/srv/example site", RemoteAction::VerifyCoreChecksums).unwrap();
        assert!(command.command.contains("--path='/srv/example site'"));
        assert!(command.command.contains("core is-installed"));
        assert!(command.command.contains("--include-root"));
        assert!(command.command.contains("--format=json"));
        assert!(!command.mutating);
    }

    #[test]
    fn user_commands_only_accept_typed_validated_values() {
        let update = build(
            "/srv/site",
            RemoteAction::UpdateUser {
                user_id: 42,
                display_name: "O'Brien <admin>".into(),
                email: "obrien@example.test".into(),
                role: Some("shop_manager".into()),
            },
        )
        .unwrap();
        assert!(update.mutating);
        assert!(update.command.contains("user update 42"));
        assert!(update.command.contains("'O'\"'\"'Brien <admin>'"));
        let preserve_roles = build(
            "/srv/site",
            RemoteAction::UpdateUser {
                user_id: 42,
                display_name: "Editor".into(),
                email: "editor@example.test".into(),
                role: None,
            },
        )
        .unwrap();
        assert!(!preserve_roles.command.contains("--role="));
        assert!(
            build(
                "/srv/site",
                RemoteAction::UpdateUser {
                    user_id: 1,
                    display_name: "Admin".into(),
                    email: "bad;id".into(),
                    role: Some("administrator".into()),
                }
            )
            .is_err()
        );

        let delete = build(
            "/srv/site",
            RemoteAction::DeleteUser {
                user_id: 42,
                reassign_to: Some(7),
            },
        )
        .unwrap();
        assert_eq!(delete.command.matches("--reassign=7").count(), 1);
        assert!(!delete.command.contains("--network"));
        assert!(
            build(
                "/srv/site",
                RemoteAction::DeleteUser {
                    user_id: 42,
                    reassign_to: Some(42)
                }
            )
            .is_err()
        );
    }

    #[test]
    fn repair_uses_exact_current_version_locale_root_and_preserves_content() {
        let command = build(
            "/srv/wordpress site",
            RemoteAction::RepairCore {
                version: "6.8.2".into(),
                locale: "nl_NL".into(),
            },
        )
        .unwrap();
        assert!(command.command.contains("--path='/srv/wordpress site'"));
        assert!(command.command.contains("--version='6.8.2'"));
        assert!(command.command.contains("--locale='nl_NL'"));
        assert!(command.command.contains("--force"));
        assert!(command.command.contains("--skip-content"));
        assert!(!command.command.contains("latest"));
        assert!(!command.command.contains("rm "));
        assert!(
            build(
                "/srv/site",
                RemoteAction::RepairCore {
                    version: "latest".into(),
                    locale: "nl_NL".into()
                }
            )
            .is_err()
        );

        let update = build(
            "/srv/wordpress site",
            RemoteAction::UpdateCoreTo {
                version: "6.9.0".into(),
            },
        )
        .unwrap();
        assert!(update.command.contains("--path='/srv/wordpress site'"));
        assert!(update.command.contains("--version='6.9.0'"));
        assert!(!update.command.contains("latest"));
    }
}
