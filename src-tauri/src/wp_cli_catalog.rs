use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, path::Path};
use tauri::{AppHandle, Manager, path::BaseDirectory};

const MAX_CATALOG_BYTES: u64 = 10 * 1024 * 1024;
const MAX_COMMANDS: usize = 50_000;
const MAX_TREE_DEPTH: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WpCliParameterDoc {
    pub parameter: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WpCliCommandNode {
    pub command: String,
    #[serde(alias = "full_command")]
    pub full_command: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub url: Option<String>,
    pub parameters: Vec<WpCliParameterDoc>,
    pub subcommands: Vec<WpCliCommandNode>,
}

#[derive(Debug, Deserialize)]
struct WpCliCatalogFile {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    #[serde(alias = "scraped_at")]
    scraped_at: Option<String>,
    global_parameters: Vec<WpCliParameterDoc>,
    commands: Vec<WpCliCommandNode>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WpCliCatalog {
    pub available: bool,
    pub source: Option<String>,
    pub scraped_at: Option<String>,
    pub root_command_count: usize,
    pub total_command_count: usize,
    pub global_parameter_count: usize,
    pub global_parameters: Vec<WpCliParameterDoc>,
    pub commands: Vec<WpCliCommandNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical_details: Option<String>,
}

impl WpCliCatalog {
    fn unavailable(message: &str, details: impl Into<String>) -> Self {
        Self {
            available: false,
            source: None,
            scraped_at: None,
            root_command_count: 0,
            total_command_count: 0,
            global_parameter_count: 0,
            global_parameters: Vec::new(),
            commands: Vec::new(),
            error: Some(message.into()),
            technical_details: Some(details.into().chars().take(2_000).collect()),
        }
    }
}

pub fn load_from_app(app: &AppHandle) -> WpCliCatalog {
    let mut candidates = Vec::new();
    for relative in ["resources/wp-cli-commands.json", "wp-cli-commands.json"] {
        if let Ok(path) = app.path().resolve(relative, BaseDirectory::Resource) {
            candidates.push(path);
        }
    }
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("wp-cli-commands.json"),
    );
    let mut seen = HashSet::new();
    for path in &candidates {
        if seen.insert(path.clone()) && path.is_file() {
            return load_from_path(path);
        }
    }
    WpCliCatalog::unavailable(
        "WP-CLI commandodatabase niet gevonden",
        "Plaats wp-cli-commands.json in src-tauri/resources/ en start de applicatie opnieuw.",
    )
}

pub fn load_from_path(path: &Path) -> WpCliCatalog {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return WpCliCatalog::unavailable(
                "WP-CLI commandodatabase niet gevonden",
                error.to_string(),
            );
        }
    };
    if metadata.len() > MAX_CATALOG_BYTES {
        return WpCliCatalog::unavailable(
            "WP-CLI commandodatabase kon niet worden geladen",
            format!("Bestand is groter dan de limiet van {MAX_CATALOG_BYTES} bytes."),
        );
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return WpCliCatalog::unavailable(
                "WP-CLI commandodatabase kon niet worden geladen",
                error.to_string(),
            );
        }
    };
    let file: WpCliCatalogFile = match serde_json::from_slice(&bytes) {
        Ok(file) => file,
        Err(error) => {
            return WpCliCatalog::unavailable(
                "WP-CLI commandodatabase kon niet worden geladen",
                error.to_string(),
            );
        }
    };
    let total_command_count = match validate_catalog(&file) {
        Ok(count) => count,
        Err(details) => {
            return WpCliCatalog::unavailable(
                "WP-CLI commandodatabase kon niet worden geladen",
                details,
            );
        }
    };
    WpCliCatalog {
        available: true,
        source: file.source,
        scraped_at: file.scraped_at,
        root_command_count: file.commands.len(),
        total_command_count,
        global_parameter_count: file.global_parameters.len(),
        global_parameters: file.global_parameters,
        commands: file.commands,
        error: None,
        technical_details: None,
    }
}

fn validate_catalog(file: &WpCliCatalogFile) -> Result<usize, String> {
    let mut count = 0;
    validate_parameters(&file.global_parameters, "global_parameters")?;
    validate_nodes(&file.commands, 0, &mut count)?;
    if count > MAX_COMMANDS {
        return Err(format!(
            "Commandodatabase bevat meer dan {MAX_COMMANDS} command nodes."
        ));
    }
    Ok(count)
}

fn validate_nodes(
    nodes: &[WpCliCommandNode],
    depth: usize,
    count: &mut usize,
) -> Result<(), String> {
    if depth > MAX_TREE_DEPTH {
        return Err(format!(
            "Commandoboom is dieper dan de limiet van {MAX_TREE_DEPTH} niveaus."
        ));
    }
    for node in nodes {
        *count = count.saturating_add(1);
        if *count > MAX_COMMANDS {
            return Err(format!(
                "Commandodatabase bevat meer dan {MAX_COMMANDS} command nodes."
            ));
        }
        if node.command.trim().is_empty() || node.full_command.trim().is_empty() {
            return Err("Een command node bevat geen geldig command/full_command.".into());
        }
        if !node.full_command.starts_with("wp ") {
            return Err(format!(
                "Ongeldig full_command in documentatiedatabase: {}",
                node.full_command
            ));
        }
        validate_parameters(&node.parameters, &node.full_command)?;
        validate_nodes(&node.subcommands, depth + 1, count)?;
    }
    Ok(())
}

fn validate_parameters(parameters: &[WpCliParameterDoc], context: &str) -> Result<(), String> {
    if parameters
        .iter()
        .any(|parameter| parameter.parameter.trim().is_empty())
    {
        return Err(format!("Lege parameter gevonden bij {context}."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("wpmm-{name}-{}.json", Uuid::new_v4()))
    }

    fn fixture() -> &'static str {
        r#"{
          "source":"https://developer.wordpress.org/cli/commands/",
          "scraped_at":"2026-08-31T12:19:13Z",
          "global_parameters":[{"parameter":"[--debug]","description":"Debug"}],
          "commands":[
            {"command":"core","full_command":"wp core","description":"Core","parameters":[],"subcommands":[
              {"command":"verify-checksums","full_command":"wp core verify-checksums","parameters":[{"parameter":"[--include-root]","description":"Root"}],"subcommands":[]}
            ]},
            {"command":"cache","full_command":"wp cache","parameters":[],"subcommands":[]}
          ]
        }"#
    }

    #[test]
    fn loads_recursive_commands_parameters_and_missing_descriptions() {
        let path = temp_file("catalog");
        fs::write(&path, fixture()).unwrap();
        let catalog = load_from_path(&path);
        assert!(catalog.available);
        assert_eq!(catalog.root_command_count, 2);
        assert_eq!(catalog.total_command_count, 3);
        assert_eq!(catalog.global_parameter_count, 1);
        assert_eq!(catalog.commands[1].description, "");
        assert!(catalog.commands[1].parameters.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn handles_missing_corrupted_and_malformed_catalogs() {
        let missing = load_from_path(&temp_file("missing"));
        assert!(!missing.available);
        assert_eq!(
            missing.error.as_deref(),
            Some("WP-CLI commandodatabase niet gevonden")
        );

        let corrupt_path = temp_file("corrupt");
        fs::write(&corrupt_path, b"{not-json").unwrap();
        assert!(!load_from_path(&corrupt_path).available);
        let _ = fs::remove_file(corrupt_path);

        let malformed_path = temp_file("malformed");
        fs::write(
            &malformed_path,
            r#"{"global_parameters":[],"commands":[{"full_command":"wp core","parameters":[],"subcommands":[]}]}"#,
        )
        .unwrap();
        assert!(!load_from_path(&malformed_path).available);
        let _ = fs::remove_file(malformed_path);
    }

    #[test]
    fn supplied_catalog_is_valid_and_recursive() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("wp-cli-commands.json");
        let catalog = load_from_path(&path);
        assert!(catalog.available, "{:?}", catalog.technical_details);
        assert!(catalog.root_command_count >= 40);
        assert!(catalog.total_command_count > catalog.root_command_count);
        assert!(catalog.global_parameter_count > 0);
    }
}
