use crate::{
    error::AppError,
    snapshots::{
        SNAPSHOT_SCHEMA_VERSION, SiteSnapshot, SnapshotChange, SnapshotChangeOrigin,
        SnapshotChangeSeverity, SnapshotChangeType, SnapshotComparisonStatus, SnapshotDiff,
        SnapshotDiffSection, SnapshotFileState, SnapshotPlugin, SnapshotSection, SnapshotTheme,
        SnapshotUser, SnapshotValue,
    },
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub struct SnapshotDiffEngine;
pub struct SnapshotDiffPolicy;

impl SnapshotDiffEngine {
    pub fn compare(
        previous: &SiteSnapshot,
        current: &SiteSnapshot,
        origin: SnapshotChangeOrigin,
        maintenance_run_id: Option<String>,
    ) -> Result<SnapshotDiff, AppError> {
        validate_comparison(previous, current)?;
        let diff_id = stable_id(
            "diff",
            &[
                &previous.metadata.snapshot_id,
                &current.metadata.snapshot_id,
            ],
        );
        let mut sections = Vec::with_capacity(SnapshotSection::ALL.len());
        let mut changes = Vec::new();
        for category in SnapshotSection::ALL {
            let comparable = previous.completeness.status_for(category).is_reliable()
                && current.completeness.status_for(category).is_reliable();
            if !comparable {
                sections.push(SnapshotDiffSection {
                    category,
                    status: SnapshotComparisonStatus::Unavailable,
                    reason: Some(format!(
                        "{} kon tijdens een van de controles niet betrouwbaar worden vergeleken.",
                        section_label(category)
                    )),
                });
                continue;
            }
            sections.push(SnapshotDiffSection {
                category,
                status: SnapshotComparisonStatus::Compared,
                reason: None,
            });
            match category {
                SnapshotSection::Core => compare_core(previous, current, origin, &mut changes),
                SnapshotSection::Plugins => {
                    compare_plugins(previous, current, origin, &mut changes)?
                }
                SnapshotSection::Themes => compare_themes(previous, current, origin, &mut changes)?,
                SnapshotSection::Users => compare_users(previous, current, origin, &mut changes)?,
                SnapshotSection::Configuration => {
                    compare_configuration(previous, current, origin, &mut changes)?
                }
                SnapshotSection::Cron => compare_cron(previous, current, origin, &mut changes)?,
                SnapshotSection::Files => compare_files(previous, current, origin, &mut changes)?,
            }
        }
        changes.sort_by(|left, right| {
            (
                left.category,
                &left.entity_key,
                &left.field,
                left.change_type,
            )
                .cmp(&(
                    right.category,
                    &right.entity_key,
                    &right.field,
                    right.change_type,
                ))
        });
        let mut diff = SnapshotDiff {
            id: diff_id,
            site_id: current.metadata.site_id.clone(),
            from_snapshot_id: previous.metadata.snapshot_id.clone(),
            to_snapshot_id: current.metadata.snapshot_id.clone(),
            created_at: current.metadata.scan_timestamp.clone(),
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            origin,
            maintenance_run_id,
            sections,
            changes,
        };
        finalize_change_context(&mut diff);
        Ok(diff)
    }
}

impl SnapshotDiffPolicy {
    fn plugin_added(plugin: &SnapshotPlugin) -> SnapshotChangeSeverity {
        if plugin.status == "active" {
            SnapshotChangeSeverity::Attention
        } else {
            SnapshotChangeSeverity::Info
        }
    }

    fn user_added(user: &SnapshotUser) -> SnapshotChangeSeverity {
        if is_administrator(user) {
            SnapshotChangeSeverity::Warning
        } else {
            SnapshotChangeSeverity::Info
        }
    }

    fn role_change(previous: &SnapshotUser, current: &SnapshotUser) -> SnapshotChangeSeverity {
        if !is_administrator(previous) && is_administrator(current) {
            SnapshotChangeSeverity::Warning
        } else if is_administrator(previous) && !is_administrator(current) {
            SnapshotChangeSeverity::Attention
        } else {
            SnapshotChangeSeverity::Info
        }
    }

    fn configuration(
        key: &str,
        old_value: Option<&SnapshotValue>,
        new_value: Option<&SnapshotValue>,
        production: bool,
    ) -> SnapshotChangeSeverity {
        let enabled = matches!(new_value, Some(SnapshotValue::Boolean(true)));
        let weakened = matches!(old_value, Some(SnapshotValue::Boolean(true)))
            && matches!(new_value, Some(SnapshotValue::Boolean(false)));
        match key {
            "WP_DEBUG" | "WP_DEBUG_DISPLAY" if enabled && production => {
                SnapshotChangeSeverity::Warning
            }
            "DISALLOW_FILE_EDIT" | "DISALLOW_FILE_MODS" if weakened => {
                SnapshotChangeSeverity::Attention
            }
            "site_url" | "home_url" => SnapshotChangeSeverity::Attention,
            _ => SnapshotChangeSeverity::Info,
        }
    }
}

fn validate_comparison(previous: &SiteSnapshot, current: &SiteSnapshot) -> Result<(), AppError> {
    if previous.metadata.site_id != current.metadata.site_id {
        return Err(snapshot_diff_error(
            "Momentopnames van verschillende websites kunnen niet worden vergeleken.",
        ));
    }
    if previous.metadata.schema_version != SNAPSHOT_SCHEMA_VERSION
        || current.metadata.schema_version != SNAPSHOT_SCHEMA_VERSION
    {
        return Err(snapshot_diff_error(
            "Een van de snapshot-schema's wordt niet ondersteund.",
        ));
    }
    if previous.metadata.snapshot_id == current.metadata.snapshot_id {
        return Err(snapshot_diff_error(
            "Een momentopname kan niet met zichzelf worden vergeleken.",
        ));
    }
    Ok(())
}

fn compare_core(
    previous: &SiteSnapshot,
    current: &SiteSnapshot,
    origin: SnapshotChangeOrigin,
    changes: &mut Vec<SnapshotChange>,
) {
    let (Some(previous), Some(current)) = (&previous.core, &current.core) else {
        return;
    };
    if previous.version != current.version {
        push_change_from_values(
            changes,
            SnapshotSection::Core,
            "wordpress",
            SnapshotChangeType::VersionChanged,
            Some("version"),
            Some(SnapshotValue::String(previous.version.clone())),
            Some(SnapshotValue::String(current.version.clone())),
            SnapshotChangeSeverity::Info,
            "WordPress-versie gewijzigd",
            origin,
        );
    }
    compare_optional_core_field(
        changes,
        previous.locale.as_deref(),
        current.locale.as_deref(),
        "locale",
        "WordPress-locale gewijzigd",
        origin,
    );
    if previous.multisite != current.multisite {
        push_change_from_values(
            changes,
            SnapshotSection::Core,
            "wordpress",
            SnapshotChangeType::Updated,
            Some("multisite"),
            previous.multisite.map(SnapshotValue::Boolean),
            current.multisite.map(SnapshotValue::Boolean),
            SnapshotChangeSeverity::Attention,
            "WordPress-multisitestatus gewijzigd",
            origin,
        );
    }
    compare_optional_core_field(
        changes,
        previous.php_version.as_deref(),
        current.php_version.as_deref(),
        "php_version",
        "PHP-versie gewijzigd",
        origin,
    );
}

fn compare_optional_core_field(
    changes: &mut Vec<SnapshotChange>,
    previous: Option<&str>,
    current: Option<&str>,
    field: &str,
    summary: &str,
    origin: SnapshotChangeOrigin,
) {
    if previous != current {
        push_change_from_values(
            changes,
            SnapshotSection::Core,
            "wordpress",
            SnapshotChangeType::Updated,
            Some(field),
            previous.map(|value| SnapshotValue::String(value.into())),
            current.map(|value| SnapshotValue::String(value.into())),
            SnapshotChangeSeverity::Info,
            summary,
            origin,
        );
    }
}

fn compare_plugins(
    previous: &SiteSnapshot,
    current: &SiteSnapshot,
    origin: SnapshotChangeOrigin,
    changes: &mut Vec<SnapshotChange>,
) -> Result<(), AppError> {
    let previous = index_by(&previous.plugins, |plugin| plugin.slug.as_str(), "plugin")?;
    let current = index_by(&current.plugins, |plugin| plugin.slug.as_str(), "plugin")?;
    for key in union_keys(&previous, &current) {
        match (previous.get(&key), current.get(&key)) {
            (None, Some(plugin)) => push_entity_change(
                changes,
                SnapshotSection::Plugins,
                key,
                SnapshotChangeType::Added,
                None,
                Some(SnapshotValue::String(plugin.version.clone())),
                SnapshotDiffPolicy::plugin_added(plugin),
                "Plugin toegevoegd",
                name_metadata(&plugin.name),
                origin,
            ),
            (Some(plugin), None) => push_entity_change(
                changes,
                SnapshotSection::Plugins,
                key,
                SnapshotChangeType::Removed,
                Some(SnapshotValue::String(plugin.version.clone())),
                None,
                SnapshotChangeSeverity::Info,
                "Plugin verwijderd",
                name_metadata(&plugin.name),
                origin,
            ),
            (Some(previous), Some(current)) => {
                compare_software_fields(
                    changes,
                    SnapshotSection::Plugins,
                    key,
                    &previous.name,
                    &previous.version,
                    &current.version,
                    &previous.status,
                    &current.status,
                    previous.auto_update,
                    current.auto_update,
                    origin,
                );
            }
            (None, None) => {}
        }
    }
    Ok(())
}

fn compare_themes(
    previous: &SiteSnapshot,
    current: &SiteSnapshot,
    origin: SnapshotChangeOrigin,
    changes: &mut Vec<SnapshotChange>,
) -> Result<(), AppError> {
    let previous = index_by(&previous.themes, |theme| theme.slug.as_str(), "thema")?;
    let current = index_by(&current.themes, |theme| theme.slug.as_str(), "thema")?;
    for key in union_keys(&previous, &current) {
        match (previous.get(&key), current.get(&key)) {
            (None, Some(theme)) => push_entity_change(
                changes,
                SnapshotSection::Themes,
                key,
                SnapshotChangeType::Added,
                None,
                Some(SnapshotValue::String(theme.version.clone())),
                SnapshotChangeSeverity::Info,
                "Thema toegevoegd",
                name_metadata(&theme.name),
                origin,
            ),
            (Some(theme), None) => push_entity_change(
                changes,
                SnapshotSection::Themes,
                key,
                SnapshotChangeType::Removed,
                Some(SnapshotValue::String(theme.version.clone())),
                None,
                SnapshotChangeSeverity::Info,
                "Thema verwijderd",
                name_metadata(&theme.name),
                origin,
            ),
            (Some(previous), Some(current)) => {
                compare_theme_fields(changes, key, previous, current, origin);
            }
            (None, None) => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compare_software_fields(
    changes: &mut Vec<SnapshotChange>,
    category: SnapshotSection,
    key: &str,
    name: &str,
    previous_version: &str,
    current_version: &str,
    previous_status: &str,
    current_status: &str,
    previous_auto_update: Option<bool>,
    current_auto_update: Option<bool>,
    origin: SnapshotChangeOrigin,
) {
    let metadata = name_metadata(name);
    if previous_version != current_version {
        push_entity_change_with_field(
            changes,
            category,
            key,
            SnapshotChangeType::VersionChanged,
            "version",
            Some(SnapshotValue::String(previous_version.into())),
            Some(SnapshotValue::String(current_version.into())),
            SnapshotChangeSeverity::Info,
            if category == SnapshotSection::Plugins {
                "Pluginversie gewijzigd"
            } else {
                "Themaversie gewijzigd"
            },
            metadata.clone(),
            origin,
        );
    }
    if previous_status != current_status {
        let activated = current_status == "active";
        push_entity_change_with_field(
            changes,
            category,
            key,
            if activated {
                SnapshotChangeType::Activated
            } else {
                SnapshotChangeType::Deactivated
            },
            "status",
            Some(SnapshotValue::String(previous_status.into())),
            Some(SnapshotValue::String(current_status.into())),
            SnapshotChangeSeverity::Info,
            if activated && category == SnapshotSection::Plugins {
                "Plugin geactiveerd"
            } else if activated {
                "Thema actief geworden"
            } else if category == SnapshotSection::Plugins {
                "Plugin gedeactiveerd"
            } else {
                "Thema gedeactiveerd"
            },
            metadata.clone(),
            origin,
        );
    }
    if previous_auto_update != current_auto_update
        && let (Some(previous), Some(current)) = (previous_auto_update, current_auto_update)
    {
        push_entity_change_with_field(
            changes,
            category,
            key,
            if current {
                SnapshotChangeType::Enabled
            } else {
                SnapshotChangeType::Disabled
            },
            "auto_update",
            Some(SnapshotValue::Boolean(previous)),
            Some(SnapshotValue::Boolean(current)),
            SnapshotChangeSeverity::Info,
            "Automatische updates gewijzigd",
            metadata,
            origin,
        );
    }
}

fn compare_theme_fields(
    changes: &mut Vec<SnapshotChange>,
    key: &str,
    previous: &SnapshotTheme,
    current: &SnapshotTheme,
    origin: SnapshotChangeOrigin,
) {
    compare_software_fields(
        changes,
        SnapshotSection::Themes,
        key,
        &current.name,
        &previous.version,
        &current.version,
        &previous.status,
        &current.status,
        previous.auto_update,
        current.auto_update,
        origin,
    );
    if previous.active != current.active && previous.status == current.status {
        push_entity_change_with_field(
            changes,
            SnapshotSection::Themes,
            key,
            if current.active {
                SnapshotChangeType::Activated
            } else {
                SnapshotChangeType::Deactivated
            },
            "active",
            Some(SnapshotValue::Boolean(previous.active)),
            Some(SnapshotValue::Boolean(current.active)),
            SnapshotChangeSeverity::Info,
            if current.active {
                "Thema actief geworden"
            } else {
                "Thema gedeactiveerd"
            },
            name_metadata(&current.name),
            origin,
        );
    }
}

fn compare_users(
    previous: &SiteSnapshot,
    current: &SiteSnapshot,
    origin: SnapshotChangeOrigin,
    changes: &mut Vec<SnapshotChange>,
) -> Result<(), AppError> {
    let previous = index_by(&previous.users, |user| user.id, "gebruiker")?;
    let current = index_by(&current.users, |user| user.id, "gebruiker")?;
    for key in union_keys(&previous, &current) {
        match (previous.get(&key), current.get(&key)) {
            (None, Some(user)) => push_entity_change(
                changes,
                SnapshotSection::Users,
                &key.to_string(),
                SnapshotChangeType::Added,
                None,
                Some(SnapshotValue::String(user.login.clone())),
                SnapshotDiffPolicy::user_added(user),
                if is_administrator(user) {
                    "Nieuwe administrator"
                } else {
                    "Nieuwe gebruiker"
                },
                user_metadata(user),
                origin,
            ),
            (Some(user), None) => push_entity_change(
                changes,
                SnapshotSection::Users,
                &key.to_string(),
                SnapshotChangeType::Removed,
                Some(SnapshotValue::String(user.login.clone())),
                None,
                SnapshotChangeSeverity::Info,
                "Gebruiker verwijderd",
                user_metadata(user),
                origin,
            ),
            (Some(previous), Some(current)) => {
                let metadata = user_metadata(current);
                if previous.roles != current.roles {
                    push_entity_change_with_field(
                        changes,
                        SnapshotSection::Users,
                        &key.to_string(),
                        SnapshotChangeType::RoleChanged,
                        "roles",
                        Some(SnapshotValue::String(previous.roles.join(","))),
                        Some(SnapshotValue::String(current.roles.join(","))),
                        SnapshotDiffPolicy::role_change(previous, current),
                        if !is_administrator(previous) && is_administrator(current) {
                            "Gebruikersrol verhoogd naar administrator"
                        } else {
                            "Gebruikersrol gewijzigd"
                        },
                        metadata.clone(),
                        origin,
                    );
                }
                compare_user_field(
                    changes,
                    key,
                    "email",
                    &previous.email,
                    &current.email,
                    "E-mailadres gewijzigd",
                    SnapshotChangeSeverity::Attention,
                    metadata.clone(),
                    origin,
                );
                compare_user_field(
                    changes,
                    key,
                    "display_name",
                    previous.display_name.as_deref().unwrap_or(""),
                    current.display_name.as_deref().unwrap_or(""),
                    "Weergavenaam gewijzigd",
                    SnapshotChangeSeverity::Info,
                    metadata,
                    origin,
                );
            }
            (None, None) => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compare_user_field(
    changes: &mut Vec<SnapshotChange>,
    key: u64,
    field: &str,
    previous: &str,
    current: &str,
    summary: &str,
    severity: SnapshotChangeSeverity,
    metadata: BTreeMap<String, SnapshotValue>,
    origin: SnapshotChangeOrigin,
) {
    if previous != current {
        push_entity_change_with_field(
            changes,
            SnapshotSection::Users,
            &key.to_string(),
            SnapshotChangeType::Updated,
            field,
            Some(SnapshotValue::String(previous.into())),
            Some(SnapshotValue::String(current.into())),
            severity,
            summary,
            metadata,
            origin,
        );
    }
}

fn compare_configuration(
    previous: &SiteSnapshot,
    current: &SiteSnapshot,
    origin: SnapshotChangeOrigin,
    changes: &mut Vec<SnapshotChange>,
) -> Result<(), AppError> {
    let previous = index_by(
        &previous.configuration,
        |item| item.key.as_str(),
        "configuratiesleutel",
    )?;
    let current = index_by(
        &current.configuration,
        |item| item.key.as_str(),
        "configuratiesleutel",
    )?;
    let production = current
        .get("wp_environment_type")
        .and_then(|item| match &item.value {
            SnapshotValue::String(value) => Some(value == "production"),
            _ => None,
        })
        .unwrap_or(true);
    for key in union_keys(&previous, &current) {
        let old_value = previous.get(&key).map(|item| item.value.clone());
        let new_value = current.get(&key).map(|item| item.value.clone());
        if old_value == new_value {
            continue;
        }
        let severity = SnapshotDiffPolicy::configuration(
            key,
            old_value.as_ref(),
            new_value.as_ref(),
            production,
        );
        push_entity_change_with_field(
            changes,
            SnapshotSection::Configuration,
            key,
            SnapshotChangeType::ConfigurationChanged,
            key,
            old_value,
            new_value,
            severity,
            &format!("{key} gewijzigd"),
            BTreeMap::new(),
            origin,
        );
    }
    Ok(())
}

fn compare_cron(
    previous: &SiteSnapshot,
    current: &SiteSnapshot,
    origin: SnapshotChangeOrigin,
    changes: &mut Vec<SnapshotChange>,
) -> Result<(), AppError> {
    let previous = index_by(&previous.cron, |event| event.identity.as_str(), "cronjob")?;
    let current = index_by(&current.cron, |event| event.identity.as_str(), "cronjob")?;
    for key in union_keys(&previous, &current) {
        match (previous.get(&key), current.get(&key)) {
            (None, Some(event)) => push_entity_change(
                changes,
                SnapshotSection::Cron,
                key.strip_prefix("cron:").unwrap_or(key),
                SnapshotChangeType::Scheduled,
                None,
                event.schedule.clone().map(SnapshotValue::String),
                SnapshotChangeSeverity::Info,
                "Cronjob ingepland",
                hook_metadata(&event.hook),
                origin,
            ),
            (Some(event), None) => push_entity_change(
                changes,
                SnapshotSection::Cron,
                key.strip_prefix("cron:").unwrap_or(key),
                SnapshotChangeType::Unscheduled,
                event.schedule.clone().map(SnapshotValue::String),
                None,
                SnapshotChangeSeverity::Info,
                "Cronjob verwijderd",
                hook_metadata(&event.hook),
                origin,
            ),
            (Some(previous), Some(current)) => {
                if previous.schedule != current.schedule
                    || previous.recurrence != current.recurrence
                {
                    push_entity_change_with_field(
                        changes,
                        SnapshotSection::Cron,
                        key.strip_prefix("cron:").unwrap_or(key),
                        SnapshotChangeType::Updated,
                        "schedule",
                        previous.schedule.clone().map(SnapshotValue::String),
                        current.schedule.clone().map(SnapshotValue::String),
                        SnapshotChangeSeverity::Info,
                        "Cronplanning gewijzigd",
                        hook_metadata(&current.hook),
                        origin,
                    );
                }
            }
            (None, None) => {}
        }
    }
    Ok(())
}

fn compare_files(
    previous: &SiteSnapshot,
    current: &SiteSnapshot,
    origin: SnapshotChangeOrigin,
    changes: &mut Vec<SnapshotChange>,
) -> Result<(), AppError> {
    let previous = index_by(
        &previous.files,
        |file| file.relative_path.as_str(),
        "bestand",
    )?;
    let current = index_by(
        &current.files,
        |file| file.relative_path.as_str(),
        "bestand",
    )?;
    for key in union_keys(&previous, &current) {
        match (previous.get(&key), current.get(&key)) {
            (None, Some(file)) => push_file_change(
                changes,
                key,
                None,
                Some(file),
                SnapshotChangeType::Added,
                "Relevant bestand toegevoegd",
                origin,
            ),
            (Some(file), None) => push_file_change(
                changes,
                key,
                Some(file),
                None,
                SnapshotChangeType::Removed,
                "Relevant bestand verwijderd",
                origin,
            ),
            (Some(previous), Some(current)) if file_changed(previous, current) => {
                push_file_change(
                    changes,
                    key,
                    Some(previous),
                    Some(current),
                    SnapshotChangeType::Updated,
                    "Relevant bestand gewijzigd",
                    origin,
                );
            }
            _ => {}
        }
    }
    Ok(())
}

fn file_changed(previous: &SnapshotFileState, current: &SnapshotFileState) -> bool {
    match (&previous.sha256, &current.sha256) {
        (Some(previous), Some(current)) => previous != current,
        _ => {
            previous.file_type != current.file_type
                || previous.size_bytes != current.size_bytes
                || previous.modified_at != current.modified_at
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_file_change(
    changes: &mut Vec<SnapshotChange>,
    key: &str,
    previous: Option<&SnapshotFileState>,
    current: Option<&SnapshotFileState>,
    change_type: SnapshotChangeType,
    summary: &str,
    origin: SnapshotChangeOrigin,
) {
    let old_value = previous.and_then(file_comparison_value);
    let new_value = current.and_then(file_comparison_value);
    let category = current
        .or(previous)
        .map(|file| file.category.clone())
        .unwrap_or_default();
    push_entity_change_with_field(
        changes,
        SnapshotSection::Files,
        key,
        change_type,
        "content",
        old_value,
        new_value,
        SnapshotChangeSeverity::Attention,
        summary,
        BTreeMap::from([("category".into(), SnapshotValue::String(category))]),
        origin,
    );
}

fn file_comparison_value(file: &SnapshotFileState) -> Option<SnapshotValue> {
    file.sha256
        .clone()
        .or_else(|| file.size_bytes.map(|size| size.to_string()))
        .map(SnapshotValue::String)
}

#[allow(clippy::too_many_arguments)]
fn push_change_from_values(
    changes: &mut Vec<SnapshotChange>,
    category: SnapshotSection,
    identity: &str,
    change_type: SnapshotChangeType,
    field: Option<&str>,
    old_value: Option<SnapshotValue>,
    new_value: Option<SnapshotValue>,
    severity: SnapshotChangeSeverity,
    summary: &str,
    origin: SnapshotChangeOrigin,
) {
    push_entity_change_internal(
        changes,
        category,
        identity,
        change_type,
        field,
        old_value,
        new_value,
        severity,
        summary,
        BTreeMap::new(),
        origin,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_entity_change(
    changes: &mut Vec<SnapshotChange>,
    category: SnapshotSection,
    identity: &str,
    change_type: SnapshotChangeType,
    old_value: Option<SnapshotValue>,
    new_value: Option<SnapshotValue>,
    severity: SnapshotChangeSeverity,
    summary: &str,
    metadata: BTreeMap<String, SnapshotValue>,
    origin: SnapshotChangeOrigin,
) {
    push_entity_change_internal(
        changes,
        category,
        identity,
        change_type,
        None,
        old_value,
        new_value,
        severity,
        summary,
        metadata,
        origin,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_entity_change_with_field(
    changes: &mut Vec<SnapshotChange>,
    category: SnapshotSection,
    identity: &str,
    change_type: SnapshotChangeType,
    field: &str,
    old_value: Option<SnapshotValue>,
    new_value: Option<SnapshotValue>,
    severity: SnapshotChangeSeverity,
    summary: &str,
    metadata: BTreeMap<String, SnapshotValue>,
    origin: SnapshotChangeOrigin,
) {
    push_entity_change_internal(
        changes,
        category,
        identity,
        change_type,
        Some(field),
        old_value,
        new_value,
        severity,
        summary,
        metadata,
        origin,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_entity_change_internal(
    changes: &mut Vec<SnapshotChange>,
    category: SnapshotSection,
    identity: &str,
    change_type: SnapshotChangeType,
    field: Option<&str>,
    old_value: Option<SnapshotValue>,
    new_value: Option<SnapshotValue>,
    severity: SnapshotChangeSeverity,
    summary: &str,
    metadata: BTreeMap<String, SnapshotValue>,
    origin: SnapshotChangeOrigin,
) {
    let entity_key = category.entity_key(identity);
    changes.push(SnapshotChange {
        id: String::new(),
        site_id: String::new(),
        from_snapshot_id: String::new(),
        to_snapshot_id: String::new(),
        category,
        entity_type: entity_type_label(category).into(),
        entity_key,
        change_type,
        field: field.map(str::to_owned),
        old_value,
        new_value,
        severity,
        summary: summary.into(),
        metadata,
        origin,
        seen: false,
        created_at: String::new(),
    });
}

fn finalize_change_context(diff: &mut SnapshotDiff) {
    for change in &mut diff.changes {
        change.site_id.clone_from(&diff.site_id);
        change.from_snapshot_id.clone_from(&diff.from_snapshot_id);
        change.to_snapshot_id.clone_from(&diff.to_snapshot_id);
        change.created_at.clone_from(&diff.created_at);
        change.id = stable_id(
            "change",
            &[
                &diff.from_snapshot_id,
                &diff.to_snapshot_id,
                &change.entity_key,
                change.field.as_deref().unwrap_or(""),
                change_type_label(change.change_type),
            ],
        );
    }
}

fn is_administrator(user: &SnapshotUser) -> bool {
    user.roles.iter().any(|role| role == "administrator")
}

fn name_metadata(name: &str) -> BTreeMap<String, SnapshotValue> {
    BTreeMap::from([("name".into(), SnapshotValue::String(name.into()))])
}

fn user_metadata(user: &SnapshotUser) -> BTreeMap<String, SnapshotValue> {
    BTreeMap::from([
        ("login".into(), SnapshotValue::String(user.login.clone())),
        ("email".into(), SnapshotValue::String(user.email.clone())),
    ])
}

fn hook_metadata(hook: &str) -> BTreeMap<String, SnapshotValue> {
    BTreeMap::from([("hook".into(), SnapshotValue::String(hook.into()))])
}

fn index_by<'a, T, K: Ord + Clone + std::fmt::Display>(
    items: &'a [T],
    key: impl Fn(&'a T) -> K,
    label: &str,
) -> Result<BTreeMap<K, &'a T>, AppError> {
    let mut indexed = BTreeMap::new();
    for item in items {
        let key = key(item);
        if indexed.insert(key.clone(), item).is_some() {
            return Err(snapshot_diff_error(format!(
                "Dubbele {label}-identiteit in snapshot: {key}."
            )));
        }
    }
    Ok(indexed)
}

fn union_keys<K: Ord + Clone, L, R>(left: &BTreeMap<K, L>, right: &BTreeMap<K, R>) -> BTreeSet<K> {
    left.keys().chain(right.keys()).cloned().collect()
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("{prefix}:{}", hex_digest(&hasher.finalize()))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn change_type_label(change_type: SnapshotChangeType) -> &'static str {
    match change_type {
        SnapshotChangeType::Added => "added",
        SnapshotChangeType::Removed => "removed",
        SnapshotChangeType::Updated => "updated",
        SnapshotChangeType::Enabled => "enabled",
        SnapshotChangeType::Disabled => "disabled",
        SnapshotChangeType::Activated => "activated",
        SnapshotChangeType::Deactivated => "deactivated",
        SnapshotChangeType::RoleChanged => "role_changed",
        SnapshotChangeType::VersionChanged => "version_changed",
        SnapshotChangeType::ConfigurationChanged => "configuration_changed",
        SnapshotChangeType::Scheduled => "scheduled",
        SnapshotChangeType::Unscheduled => "unscheduled",
        SnapshotChangeType::Unknown => "unknown",
    }
}

fn section_label(section: SnapshotSection) -> &'static str {
    match section {
        SnapshotSection::Core => "WordPress Core",
        SnapshotSection::Plugins => "Plugins",
        SnapshotSection::Themes => "Thema's",
        SnapshotSection::Users => "Gebruikers",
        SnapshotSection::Configuration => "Configuratie",
        SnapshotSection::Cron => "Cron",
        SnapshotSection::Files => "Bestanden",
    }
}

fn entity_type_label(section: SnapshotSection) -> &'static str {
    match section {
        SnapshotSection::Core => "core",
        SnapshotSection::Plugins => "plugin",
        SnapshotSection::Themes => "theme",
        SnapshotSection::Users => "user",
        SnapshotSection::Configuration => "configuration",
        SnapshotSection::Cron => "cron",
        SnapshotSection::Files => "file",
    }
}

fn snapshot_diff_error(message: impl Into<String>) -> AppError {
    AppError {
        error_id: None,
        category: "snapshot_diff".into(),
        user_message: message.into(),
        technical_details: None,
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::{
        SnapshotCompleteness, SnapshotConfiguration, SnapshotCore, SnapshotCronEvent,
        SnapshotMetadata, SnapshotPlugin, SnapshotSectionStatus, SnapshotStatus, SnapshotTheme,
        SnapshotUser,
    };

    fn snapshot(id: &str) -> SiteSnapshot {
        SiteSnapshot {
            metadata: SnapshotMetadata {
                snapshot_id: id.into(),
                site_id: "site-1".into(),
                created_at: format!("2026-09-15T0{}:00:00Z", if id == "a" { 8 } else { 9 }),
                scan_run_id: None,
                maintenance_run_id: None,
                source: crate::snapshots::SnapshotSource::Scan,
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                status: SnapshotStatus::Complete,
                wordpress_root_identity: Some("sha256:root".into()),
                scan_timestamp: format!("2026-09-15T0{}:00:00Z", if id == "a" { 8 } else { 9 }),
                app_version: Some("0.11.0-beta.1".into()),
                is_baseline: id == "a",
                previous_snapshot_id: None,
            },
            completeness: SnapshotCompleteness {
                core: SnapshotSectionStatus::Complete,
                plugins: SnapshotSectionStatus::Complete,
                themes: SnapshotSectionStatus::Complete,
                users: SnapshotSectionStatus::Complete,
                configuration: SnapshotSectionStatus::Complete,
                cron: SnapshotSectionStatus::Complete,
                files: SnapshotSectionStatus::Complete,
            },
            core: Some(SnapshotCore {
                version: "6.8.1".into(),
                locale: Some("nl_NL".into()),
                multisite: Some(false),
                php_version: Some("8.3".into()),
            }),
            plugins: Vec::new(),
            themes: Vec::new(),
            users: Vec::new(),
            configuration: Vec::new(),
            cron: Vec::new(),
            files: Vec::new(),
        }
    }

    fn compare(previous: &SiteSnapshot, current: &SiteSnapshot) -> SnapshotDiff {
        SnapshotDiffEngine::compare(previous, current, SnapshotChangeOrigin::Scan, None).unwrap()
    }

    #[test]
    fn identical_snapshots_have_no_meaningful_changes() {
        let previous = snapshot("a");
        let mut current = previous.clone();
        current.metadata.snapshot_id = "b".into();
        current.metadata.scan_timestamp = "2026-09-15T09:00:00Z".into();
        let diff = compare(&previous, &current);
        assert!(diff.changes.is_empty());
        assert!(
            diff.sections
                .iter()
                .all(|section| section.status == SnapshotComparisonStatus::Compared)
        );
    }

    #[test]
    fn plugin_changes_are_specific() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        previous.plugins = vec![
            SnapshotPlugin {
                slug: "woocommerce".into(),
                name: "WooCommerce".into(),
                version: "10.1".into(),
                status: "active".into(),
                auto_update: Some(false),
                update_available: true,
                available_version: Some("10.2".into()),
            },
            SnapshotPlugin {
                slug: "removed".into(),
                name: "Removed".into(),
                version: "1".into(),
                status: "inactive".into(),
                auto_update: None,
                update_available: false,
                available_version: None,
            },
        ];
        current.plugins = vec![
            SnapshotPlugin {
                slug: "woocommerce".into(),
                name: "WooCommerce".into(),
                version: "10.2".into(),
                status: "inactive".into(),
                auto_update: Some(true),
                update_available: false,
                available_version: None,
            },
            SnapshotPlugin {
                slug: "query-monitor".into(),
                name: "Query Monitor".into(),
                version: "3.17".into(),
                status: "active".into(),
                auto_update: None,
                update_available: false,
                available_version: None,
            },
        ];
        let diff = compare(&previous, &current);
        let types = diff
            .changes
            .iter()
            .filter(|change| change.category == SnapshotSection::Plugins)
            .map(|change| change.change_type)
            .collect::<Vec<_>>();
        assert_eq!(types.len(), 5);
        assert!(types.contains(&SnapshotChangeType::Added));
        assert!(types.contains(&SnapshotChangeType::Removed));
        assert!(types.contains(&SnapshotChangeType::VersionChanged));
        assert!(types.contains(&SnapshotChangeType::Deactivated));
        assert!(types.contains(&SnapshotChangeType::Enabled));
    }

    #[test]
    fn theme_activation_is_meaningful_without_duplicate_changes() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        previous.themes = vec![theme("astra", true), theme("generatepress", false)];
        current.themes = vec![theme("astra", false), theme("generatepress", true)];
        let diff = compare(&previous, &current);
        let theme_changes = diff
            .changes
            .iter()
            .filter(|change| change.category == SnapshotSection::Themes)
            .collect::<Vec<_>>();
        assert_eq!(theme_changes.len(), 2);
        assert_eq!(
            theme_changes
                .iter()
                .filter(|change| change.change_type == SnapshotChangeType::Activated)
                .count(),
            1
        );
    }

    #[test]
    fn new_and_promoted_administrators_receive_warning_severity() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        previous.users = vec![user(1, "editor", &["editor"])];
        current.users = vec![
            user(1, "editor", &["administrator"]),
            user(2, "new-admin", &["administrator"]),
            user(3, "subscriber", &["subscriber"]),
        ];
        let diff = compare(&previous, &current);
        let warnings = diff
            .changes
            .iter()
            .filter(|change| change.severity == SnapshotChangeSeverity::Warning)
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 2);
        assert!(
            warnings
                .iter()
                .any(|change| change.summary == "Nieuwe administrator")
        );
        assert!(warnings.iter().any(|change| {
            change.change_type == SnapshotChangeType::RoleChanged
                && change.summary.contains("verhoogd")
        }));
    }

    #[test]
    fn production_debug_enablement_is_a_warning() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        previous.configuration = config(false);
        current.configuration = config(true);
        let diff = compare(&previous, &current);
        let change = diff
            .changes
            .iter()
            .find(|change| change.entity_key == "config:WP_DEBUG")
            .unwrap();
        assert_eq!(change.change_type, SnapshotChangeType::ConfigurationChanged);
        assert_eq!(change.severity, SnapshotChangeSeverity::Warning);
    }

    #[test]
    fn core_user_and_file_fields_produce_typed_changes() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        current.core.as_mut().unwrap().version = "6.8.2".into();
        previous.users = vec![user(1, "editor", &["editor"])];
        current.users = previous.users.clone();
        current.users[0].email = "new-address@example.test".into();
        current.users[0].display_name = Some("New display name".into());
        previous.files = vec![file("wp-content/security.php", 'a')];
        current.files = vec![file("wp-content/security.php", 'b')];
        let diff = compare(&previous, &current);
        assert!(diff.changes.iter().any(|change| {
            change.entity_key == "core:wordpress"
                && change.change_type == SnapshotChangeType::VersionChanged
        }));
        assert!(diff.changes.iter().any(|change| {
            change.entity_key == "user:1" && change.field.as_deref() == Some("email")
        }));
        assert!(diff.changes.iter().any(|change| {
            change.entity_key == "user:1" && change.field.as_deref() == Some("display_name")
        }));
        assert!(diff.changes.iter().any(|change| {
            change.entity_key == "file:wp-content/security.php"
                && change.change_type == SnapshotChangeType::Updated
        }));
    }

    #[test]
    fn cron_next_run_is_volatile_but_schedule_is_not() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        previous.cron = vec![cron("daily", "2026-09-15T08:00:00Z")];
        current.cron = vec![cron("daily", "2026-09-16T08:00:00Z")];
        assert!(compare(&previous, &current).changes.is_empty());
        current.cron[0].schedule = Some("hourly".into());
        let diff = compare(&previous, &current);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, SnapshotChangeType::Updated);
    }

    #[test]
    fn cron_addition_and_removal_are_distinct() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        previous.cron = vec![cron("daily", "2026-09-15T08:00:00Z")];
        current.cron = vec![SnapshotCronEvent {
            identity: "cron:new".into(),
            hook: "new_hook".into(),
            schedule: Some("hourly".into()),
            recurrence: Some("3600".into()),
            args_fingerprint: None,
            next_run_at: Some("2026-09-15T09:00:00Z".into()),
        }];
        let diff = compare(&previous, &current);
        assert_eq!(diff.changes.len(), 2);
        assert!(
            diff.changes
                .iter()
                .any(|change| change.change_type == SnapshotChangeType::Scheduled)
        );
        assert!(
            diff.changes
                .iter()
                .any(|change| change.change_type == SnapshotChangeType::Unscheduled)
        );
    }

    #[test]
    fn partial_user_section_never_removes_users() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        previous.users = vec![
            user(1, "admin", &["administrator"]),
            user(2, "editor", &["editor"]),
        ];
        current.completeness.users = SnapshotSectionStatus::Failed;
        current.users.clear();
        let diff = compare(&previous, &current);
        assert!(
            diff.changes
                .iter()
                .all(|change| change.category != SnapshotSection::Users)
        );
        let users = diff
            .sections
            .iter()
            .find(|section| section.category == SnapshotSection::Users)
            .unwrap();
        assert_eq!(users.status, SnapshotComparisonStatus::Unavailable);
        assert!(
            users
                .reason
                .as_deref()
                .unwrap()
                .contains("niet betrouwbaar")
        );
    }

    #[test]
    fn comparison_is_deterministic_and_order_independent() {
        let mut previous = snapshot("a");
        let mut current = snapshot("b");
        previous.plugins = vec![plugin("z", "1"), plugin("a", "1")];
        current.plugins = vec![plugin("a", "2"), plugin("z", "2")];
        let first = compare(&previous, &current);
        current.plugins.reverse();
        let second = compare(&previous, &current);
        assert_eq!(first, second);
        assert_eq!(first.changes[0].entity_key, "plugin:a");
    }

    fn plugin(slug: &str, version: &str) -> SnapshotPlugin {
        SnapshotPlugin {
            slug: slug.into(),
            name: slug.into(),
            version: version.into(),
            status: "active".into(),
            auto_update: None,
            update_available: false,
            available_version: None,
        }
    }

    fn theme(slug: &str, active: bool) -> SnapshotTheme {
        SnapshotTheme {
            slug: slug.into(),
            name: slug.into(),
            version: "1".into(),
            status: if active { "active" } else { "inactive" }.into(),
            active,
            auto_update: None,
            update_available: false,
            available_version: None,
        }
    }

    fn user(id: u64, login: &str, roles: &[&str]) -> SnapshotUser {
        SnapshotUser {
            id,
            login: login.into(),
            display_name: Some(login.into()),
            email: format!("{login}@example.test"),
            roles: roles.iter().map(|role| (*role).into()).collect(),
            registered_at: None,
        }
    }

    fn config(debug: bool) -> Vec<SnapshotConfiguration> {
        vec![
            SnapshotConfiguration {
                key: "WP_DEBUG".into(),
                value: SnapshotValue::Boolean(debug),
            },
            SnapshotConfiguration {
                key: "wp_environment_type".into(),
                value: SnapshotValue::String("production".into()),
            },
        ]
    }

    fn cron(schedule: &str, next_run_at: &str) -> SnapshotCronEvent {
        SnapshotCronEvent {
            identity: "cron:stable".into(),
            hook: "example_hook".into(),
            schedule: Some(schedule.into()),
            recurrence: Some("86400".into()),
            args_fingerprint: None,
            next_run_at: Some(next_run_at.into()),
        }
    }

    fn file(path: &str, hash_character: char) -> SnapshotFileState {
        SnapshotFileState {
            relative_path: path.into(),
            category: "security".into(),
            file_type: "regular".into(),
            size_bytes: Some(100),
            modified_at: Some("2026-09-15T08:00:00Z".into()),
            sha256: Some(hash_character.to_string().repeat(64)),
        }
    }
}
