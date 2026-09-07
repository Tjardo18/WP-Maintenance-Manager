use crate::{
    command_catalog::{RemoteCommand, shell_escape},
    error::AppError,
    validation::validate_wordpress_path,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 1_024;
const MAX_ARGUMENT_BYTES: usize = 32 * 1024;
const CONSOLE_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WpCliRisk {
    ReadOnly,
    Mutating,
    HighRisk,
}

impl WpCliRisk {
    pub fn as_audit(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Mutating => "mutating",
            Self::HighRisk => "high_risk",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WpCliCommandInspection {
    pub risk: WpCliRisk,
    pub command_family: String,
    pub summary: String,
    pub requires_confirmation: bool,
    pub requires_typed_confirmation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_phrase: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WpCliExecutionStatus {
    Success,
    Warning,
    Failed,
}

impl WpCliExecutionStatus {
    pub fn as_audit(self) -> &'static str {
        match self {
            Self::Success | Self::Warning => "success",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WpCliExecutionResult {
    pub status: WpCliExecutionStatus,
    pub risk: WpCliRisk,
    pub command_family: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub started_at: String,
    pub finished_at: String,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct PreparedWpCliCommand {
    pub remote_command: RemoteCommand,
    pub inspection: WpCliCommandInspection,
}

pub fn inspect_command(
    input: &str,
    wordpress_path: &str,
) -> Result<WpCliCommandInspection, AppError> {
    Ok(prepare_command(input, wordpress_path)?.inspection)
}

pub fn prepare_command(
    input: &str,
    wordpress_path: &str,
) -> Result<PreparedWpCliCommand, AppError> {
    validate_wordpress_path(wordpress_path)?;
    let argv = parse_wp_cli_argv(input)?;
    validate_site_routing(&argv)?;
    let inspection = classify_command(&argv);
    let mut command = format!(
        "LC_ALL=C wp --no-color --path={}",
        shell_escape(wordpress_path)
    );
    for argument in argv.iter().skip(1) {
        command.push(' ');
        command.push_str(&shell_escape(argument));
    }
    let timeout = match inspection.risk {
        WpCliRisk::ReadOnly => Duration::from_secs(180),
        WpCliRisk::Mutating => Duration::from_secs(600),
        WpCliRisk::HighRisk => Duration::from_secs(900),
    };
    Ok(PreparedWpCliCommand {
        remote_command: RemoteCommand {
            action_name: "ExecuteWpCliConsole",
            command,
            mutating: inspection.risk != WpCliRisk::ReadOnly,
            timeout,
            max_output_bytes: CONSOLE_OUTPUT_BYTES,
            truncate_output: true,
        },
        inspection,
    })
}

pub fn validate_confirmation(
    inspection: &WpCliCommandInspection,
    confirmed: bool,
    typed_confirmation: Option<&str>,
) -> Result<(), AppError> {
    match inspection.risk {
        WpCliRisk::ReadOnly => Ok(()),
        WpCliRisk::Mutating if confirmed => Ok(()),
        WpCliRisk::HighRisk
            if confirmed && typed_confirmation.is_some_and(|value| value == "UITVOEREN") =>
        {
            Ok(())
        }
        WpCliRisk::HighRisk => Err(AppError::validation(
            "Typ UITVOEREN om dit hoog-risico WP-CLI-commando te bevestigen.",
        )),
        WpCliRisk::Mutating => Err(AppError::validation(
            "Bevestig dit muterende WP-CLI-commando voordat je het uitvoert.",
        )),
    }
}

pub fn parse_wp_cli_argv(input: &str) -> Result<Vec<String>, AppError> {
    if input.len() > MAX_COMMAND_BYTES {
        return Err(AppError::validation(format!(
            "Het WP-CLI-commando is langer dan {MAX_COMMAND_BYTES} bytes."
        )));
    }
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                } else {
                    current.push(character);
                }
            }
            Some('"') => {
                if character == '"' {
                    quote = None;
                } else if character == '\\' {
                    let escaped = characters.next().ok_or_else(|| {
                        AppError::validation("Het commando eindigt met een onvolledige escape.")
                    })?;
                    current.push(escaped);
                } else {
                    current.push(character);
                }
            }
            Some(_) => unreachable!(),
            None => {
                if character.is_whitespace() {
                    if matches!(character, '\r' | '\n') {
                        return Err(shell_operator_error());
                    }
                    if started {
                        push_argument(&mut arguments, &mut current)?;
                        started = false;
                    }
                    continue;
                }
                started = true;
                match character {
                    '\'' | '"' => quote = Some(character),
                    '\\' => {
                        let escaped = characters.next().ok_or_else(|| {
                            AppError::validation("Het commando eindigt met een onvolledige escape.")
                        })?;
                        current.push(escaped);
                    }
                    ';' | '|' | '&' | '>' | '<' | '`' => return Err(shell_operator_error()),
                    '$' if characters.peek() == Some(&'(') => return Err(shell_operator_error()),
                    _ => current.push(character),
                }
            }
        }
    }
    if quote.is_some() {
        return Err(AppError::validation(
            "Het WP-CLI-commando bevat een niet-afgesloten quote.",
        ));
    }
    if started {
        push_argument(&mut arguments, &mut current)?;
    }
    if arguments.first().map(String::as_str) != Some("wp") {
        return Err(AppError::validation(
            "Een consolecommando moet beginnen met exact `wp`.",
        ));
    }
    if arguments.len() > MAX_ARGUMENTS {
        return Err(AppError::validation(format!(
            "Het WP-CLI-commando bevat meer dan {MAX_ARGUMENTS} argumenten."
        )));
    }
    Ok(arguments)
}

fn push_argument(arguments: &mut Vec<String>, current: &mut String) -> Result<(), AppError> {
    if current.len() > MAX_ARGUMENT_BYTES {
        return Err(AppError::validation(format!(
            "Een WP-CLI-argument is langer dan {MAX_ARGUMENT_BYTES} bytes."
        )));
    }
    arguments.push(std::mem::take(current));
    Ok(())
}

fn shell_operator_error() -> AppError {
    AppError::validation(
        "Algemene shelloperators, redirects en command chaining zijn niet toegestaan.",
    )
}

fn validate_site_routing(argv: &[String]) -> Result<(), AppError> {
    let mut found_command = false;
    for argument in argv.iter().skip(1) {
        let option = argument
            .split_once('=')
            .map_or(argument.as_str(), |value| value.0);
        if matches!(option, "--path" | "--ssh" | "--http") {
            return Err(AppError::validation(
                "De geselecteerde site, SSH-verbinding en WordPress-root worden door de backend bepaald; laat --path, --ssh en --http weg.",
            ));
        }
        if !found_command && argument.starts_with('@') {
            return Err(AppError::validation(
                "WP-CLI-aliases zijn niet toegestaan omdat de geselecteerde site backend-side wordt bepaald.",
            ));
        }
        if !argument.starts_with('-') {
            found_command = true;
        }
    }
    Ok(())
}

fn classify_command(argv: &[String]) -> WpCliCommandInspection {
    let words: Vec<&str> = argv
        .iter()
        .skip(1)
        .filter(|argument| !argument.starts_with('-'))
        .map(String::as_str)
        .collect();
    let family = words.first().copied().unwrap_or("help");
    let action = words.get(1).copied().unwrap_or("");
    let high_risk = argv.iter().skip(1).any(|argument| {
        let option = argument
            .split_once('=')
            .map_or(argument.as_str(), |value| value.0);
        matches!(option, "--exec" | "--require")
    }) || matches!(family, "eval" | "eval-file" | "shell")
        || matches!(
            (family, action),
            ("db", "query" | "drop" | "reset" | "clean" | "import")
                | ("config", "create" | "set" | "delete")
                | ("core", "download" | "update")
                | ("cli", "update")
                | ("search-replace", _)
        );
    let risk = if high_risk {
        WpCliRisk::HighRisk
    } else if is_known_read_only(family, action) {
        WpCliRisk::ReadOnly
    } else {
        WpCliRisk::Mutating
    };
    let (summary, requires_confirmation, requires_typed_confirmation) = match risk {
        WpCliRisk::ReadOnly => (
            "Alleen-lezen of normale WP-CLI-controle.".into(),
            false,
            false,
        ),
        WpCliRisk::Mutating => (
            "Dit commando kan de geselecteerde WordPress-site wijzigen.".into(),
            true,
            false,
        ),
        WpCliRisk::HighRisk => (
            "Dit krachtige WP-CLI-commando kan ingrijpende of destructieve wijzigingen uitvoeren."
                .into(),
            true,
            true,
        ),
    };
    WpCliCommandInspection {
        risk,
        command_family: audit_safe_family(family),
        summary,
        requires_confirmation,
        requires_typed_confirmation,
        confirmation_phrase: requires_typed_confirmation.then(|| "UITVOEREN".into()),
    }
}

fn is_known_read_only(family: &str, action: &str) -> bool {
    if matches!(family, "help" | "info" | "status") || (family == "cli" && action == "version") {
        return true;
    }
    let known_family = matches!(
        family,
        "ability"
            | "cache"
            | "cap"
            | "cli"
            | "comment"
            | "config"
            | "core"
            | "cron"
            | "db"
            | "media"
            | "menu"
            | "network"
            | "option"
            | "package"
            | "plugin"
            | "post"
            | "post-type"
            | "rewrite"
            | "role"
            | "site"
            | "taxonomy"
            | "term"
            | "theme"
            | "transient"
            | "user"
            | "widget"
    );
    known_family
        && matches!(
            action,
            "check"
                | "check-update"
                | "cmd-dump"
                | "count"
                | "exists"
                | "get"
                | "has-cap"
                | "info"
                | "is-active"
                | "is-installed"
                | "list"
                | "path"
                | "search"
                | "size"
                | "status"
                | "tables"
                | "verify-checksums"
                | "version"
        )
}

fn audit_safe_family(family: &str) -> String {
    if family.len() <= 64
        && !family.is_empty()
        && family
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        family.to_ascii_lowercase()
    } else {
        "custom".into()
    }
}

pub fn sanitize_output(bytes: &[u8]) -> String {
    let value = String::from_utf8_lossy(bytes);
    let mut clean = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' {
            if characters.peek() == Some(&'[') {
                let _ = characters.next();
                for escaped in characters.by_ref() {
                    if ('@'..='~').contains(&escaped) {
                        break;
                    }
                }
            } else {
                let _ = characters.next();
            }
            continue;
        }
        if !character.is_control() || matches!(character, '\n' | '\r' | '\t') {
            clean.push(character);
        }
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(input: &str) -> Vec<String> {
        parse_wp_cli_argv(input).unwrap()
    }

    #[test]
    fn parses_quotes_escapes_unicode_and_legitimate_wp_cli_code() {
        assert_eq!(
            allowed("wp core version --debug"),
            ["wp", "core", "version", "--debug"]
        );
        assert_eq!(
            allowed("wp db query \"SELECT * FROM wp_posts WHERE ID > 100;\""),
            [
                "wp",
                "db",
                "query",
                "SELECT * FROM wp_posts WHERE ID > 100;"
            ]
        );
        assert_eq!(
            allowed("wp eval 'echo \"héllo\";'"),
            ["wp", "eval", "echo \"héllo\";"]
        );
        assert_eq!(
            allowed(r"wp option get some\ value"),
            ["wp", "option", "get", "some value"]
        );
        assert_eq!(allowed("wp eval 'system(\"id\");' ")[2], "system(\"id\");");
    }

    #[test]
    fn rejects_non_wp_executables_shell_operators_and_malformed_input() {
        for input in [
            "rm -rf /",
            "bash",
            "php -r test",
            "wp core version && rm file",
            "wp core version; rm file",
            "wp core version | cat",
            "wp core version > file.txt",
            "wp core version || true",
            "wp core version `id`",
            "wp core version $(id)",
            "wp core version\nrm file",
            "wp eval 'unterminated",
            "wp core version \\",
        ] {
            assert!(parse_wp_cli_argv(input).is_err(), "moet weigeren: {input}");
        }
    }

    #[test]
    fn quoted_or_escaped_operator_characters_are_safe_arguments() {
        assert_eq!(allowed("wp option get 'a;b|c>d'")[3], "a;b|c>d");
        assert_eq!(allowed(r"wp option get a\;b")[3], "a;b");
    }

    #[test]
    fn enforces_input_argument_and_site_routing_limits() {
        assert!(parse_wp_cli_argv(&format!("wp {}", "x".repeat(MAX_ARGUMENT_BYTES + 1))).is_err());
        assert!(parse_wp_cli_argv(&format!("wp {}", "x ".repeat(MAX_ARGUMENTS))).is_err());
        assert!(prepare_command("wp core version --path=/tmp", "/srv/site").is_err());
        assert!(prepare_command("wp --ssh=other core version", "/srv/site").is_err());
        assert!(prepare_command("wp @production core version", "/srv/site").is_err());
    }

    #[test]
    fn rebuilds_a_backend_owned_safely_quoted_remote_command() {
        let prepared =
            prepare_command("wp eval 'system(\"id\");'", "/home/example/site root").unwrap();
        assert!(
            prepared
                .remote_command
                .command
                .starts_with("LC_ALL=C wp --no-color --path='/home/example/site root'")
        );
        assert!(
            prepared
                .remote_command
                .command
                .ends_with("'eval' 'system(\"id\");'")
        );
        assert_eq!(prepared.inspection.risk, WpCliRisk::HighRisk);
        assert!(prepared.remote_command.truncate_output);
    }

    #[test]
    fn classifies_read_mutating_unknown_and_high_risk_commands_conservatively() {
        for command in [
            "wp core version",
            "wp plugin list",
            "wp user list",
            "wp option get siteurl",
            "wp core verify-checksums --include-root",
            "wp core check-update",
        ] {
            assert_eq!(
                inspect_command(command, "/srv/site").unwrap().risk,
                WpCliRisk::ReadOnly,
                "{command}"
            );
        }
        for command in [
            "wp plugin install seo",
            "wp user delete 5",
            "wp acme custom-command",
        ] {
            assert_eq!(
                inspect_command(command, "/srv/site").unwrap().risk,
                WpCliRisk::Mutating,
                "{command}"
            );
        }
        for command in [
            "wp eval 'echo 1;'",
            "wp eval-file script.php",
            "wp db query \"SELECT 1;\"",
            "wp db drop --yes",
            "wp db reset --yes",
            "wp db clean --yes",
            "wp db import backup.sql",
            "wp config set WP_DEBUG true",
            "wp core download --force",
            "wp core update",
            "wp cli update",
            "wp core version --exec='echo 1;'",
            "wp core version --require=bootstrap.php",
        ] {
            assert_eq!(
                inspect_command(command, "/srv/site").unwrap().risk,
                WpCliRisk::HighRisk,
                "{command}"
            );
        }
    }

    #[test]
    fn requires_backend_confirmation_for_mutating_and_high_risk_commands() {
        let mutating = inspect_command("wp plugin install seo", "/srv/site").unwrap();
        assert!(validate_confirmation(&mutating, false, None).is_err());
        assert!(validate_confirmation(&mutating, true, None).is_ok());
        let high = inspect_command("wp db reset --yes", "/srv/site").unwrap();
        assert!(validate_confirmation(&high, true, Some("uitvoeren")).is_err());
        assert!(validate_confirmation(&high, true, Some("UITVOEREN")).is_ok());
    }

    #[test]
    fn sanitizes_ansi_controls_but_preserves_untrusted_html_as_text() {
        let clean = sanitize_output(b"\x1b[31m<script>alert(1)</script>\x1b[0m\0\n");
        assert_eq!(clean, "<script>alert(1)</script>\n");
    }
}
