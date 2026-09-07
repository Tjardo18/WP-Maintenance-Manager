use crate::{
    command_catalog::{RemoteAction, build},
    engine::{checked_output, text_action},
    error::AppError,
    models::{StoredSite, WordPressUserDeleteInput, WordPressUserUpdateInput, WordPressUsersData},
    parsers,
    ssh::SshExecutor,
    validation::{validate_display_name, validate_email, validate_role, validate_user_id},
};

pub fn load(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
) -> Result<WordPressUsersData, AppError> {
    executor.authenticate(&stored.site, credential)?;
    load_authenticated(executor, stored, credential)
}

pub fn update(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    input: &WordPressUserUpdateInput,
) -> Result<WordPressUsersData, AppError> {
    validate_user_id(input.user_id)?;
    validate_display_name(&input.display_name)?;
    validate_email(&input.email)?;
    if let Some(role) = input.role.as_deref() {
        validate_role(role)?;
    }
    let current = load(executor, stored, credential)?;
    let target = current
        .users
        .iter()
        .find(|user| user.id == input.user_id)
        .ok_or_else(|| AppError::not_found("WordPress-gebruiker"))?;
    if let Some(role) = input.role.as_deref()
        && !current.roles.iter().any(|available| available.role == role)
    {
        return Err(AppError::validation(
            "Deze rol bestaat niet op de huidige WordPress-site.",
        ));
    }
    let target_is_admin = is_administrator(&target.roles);
    if target_is_admin
        && input
            .role
            .as_deref()
            .is_some_and(|role| role != "administrator")
        && administrator_count(&current) <= 1
    {
        return Err(AppError::validation(
            "De rol kan niet worden gewijzigd omdat dit het laatste Administrator-account is.",
        ));
    }
    checked_output(
        executor,
        &stored.site,
        credential,
        build(
            &stored.site.wordpress_path,
            RemoteAction::UpdateUser {
                user_id: input.user_id,
                display_name: input.display_name.clone(),
                email: input.email.clone(),
                role: input.role.clone(),
            },
        )?,
    )?;
    load_authenticated(executor, stored, credential)
}

pub fn delete(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    input: &WordPressUserDeleteInput,
) -> Result<WordPressUsersData, AppError> {
    validate_user_id(input.user_id)?;
    if input.delete_content == input.reassign_to.is_some() {
        return Err(AppError::validation(
            "Kies óf contenttoewijzing óf het verwijderen van gekoppelde content.",
        ));
    }
    let current = load(executor, stored, credential)?;
    let target = current
        .users
        .iter()
        .find(|user| user.id == input.user_id)
        .ok_or_else(|| AppError::not_found("WordPress-gebruiker"))?;
    if is_administrator(&target.roles) && administrator_count(&current) <= 1 {
        return Err(AppError::validation(
            "Deze gebruiker kan niet worden verwijderd omdat dit het laatste Administrator-account is.",
        ));
    }
    if let Some(reassign_to) = input.reassign_to {
        validate_user_id(reassign_to)?;
        if reassign_to == input.user_id {
            return Err(AppError::validation(
                "Content kan niet aan dezelfde gebruiker worden toegewezen.",
            ));
        }
        if !current.users.iter().any(|user| user.id == reassign_to) {
            return Err(AppError::validation(
                "De gebruiker voor contenttoewijzing bestaat niet op deze site.",
            ));
        }
    }
    checked_output(
        executor,
        &stored.site,
        credential,
        build(
            &stored.site.wordpress_path,
            RemoteAction::DeleteUser {
                user_id: input.user_id,
                reassign_to: input.reassign_to,
            },
        )?,
    )?;
    load_authenticated(executor, stored, credential)
}

fn load_authenticated(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
) -> Result<WordPressUsersData, AppError> {
    let users = parsers::parse_wordpress_users(&text_action(
        executor,
        stored,
        credential,
        RemoteAction::ListUsers,
    )?)?;
    let roles = parsers::parse_wordpress_roles(&text_action(
        executor,
        stored,
        credential,
        RemoteAction::ListRoles,
    )?)?;
    let multisite = parsers::parse_multisite(&text_action(
        executor,
        stored,
        credential,
        RemoteAction::DetectMultisite,
    )?)?;
    Ok(WordPressUsersData {
        users,
        roles,
        multisite,
    })
}

fn administrator_count(data: &WordPressUsersData) -> usize {
    data.users
        .iter()
        .filter(|user| is_administrator(&user.roles))
        .count()
}

fn is_administrator(roles: &[String]) -> bool {
    roles.iter().any(|role| role == "administrator")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command_catalog::RemoteCommand,
        models::{AuthMethod, Site},
        ssh::ExecOutput,
    };
    use std::{path::Path, sync::Mutex};

    struct UserMockSsh {
        users_json: String,
        multisite: bool,
        mutations: Mutex<Vec<String>>,
    }

    impl SshExecutor for UserMockSsh {
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
            let stdout = match command.action_name {
                "ListUsers" => self.users_json.as_bytes().to_vec(),
                "ListRoles" => br#"[{"role":"administrator","name":"Administrator"},{"role":"editor","name":"Editor"}]"#.to_vec(),
                "DetectMultisite" => if self.multisite { b"1".to_vec() } else { b"0".to_vec() },
                _ => {
                    self.mutations.lock().unwrap().push(command.command.clone());
                    b"Success".to_vec()
                }
            };
            Ok(ExecOutput {
                stdout,
                stderr: Vec::new(),
                exit_code: 0,
                truncated: false,
            })
        }

        fn download(&self, _: &Site, _: Option<&str>, _: &str, _: &Path) -> Result<u64, AppError> {
            Ok(0)
        }
    }

    fn stored() -> StoredSite {
        StoredSite {
            site: Site {
                id: "site".into(),
                name: "Site".into(),
                url: "https://example.test".into(),
                ssh_host: "example.test".into(),
                ssh_port: 22,
                ssh_username: "deploy".into(),
                auth_method: AuthMethod::KeyFile,
                key_path: Some("key".into()),
                wordpress_path: "/srv/site".into(),
                pinned_host_key: Some("SHA256:test".into()),
                status: crate::models::SiteStatus::Healthy,
                wordpress_version: Some("6.8.2".into()),
                php_version: Some("8.3".into()),
                update_count: 0,
                security_status: None,
                last_scan_at: None,
                last_maintenance_at: None,
                created_at: "now".into(),
                updated_at: "now".into(),
            },
            credential_ref: None,
        }
    }

    fn user_json(second_admin: bool) -> String {
        let second_role = if second_admin {
            "administrator"
        } else {
            "editor"
        };
        format!(
            r#"[{{"ID":1,"user_login":"admin","display_name":"Admin","user_email":"admin@example.test","roles":["administrator"],"user_registered":"2020-01-01 00:00:00"}},{{"ID":2,"user_login":"editor","display_name":"Editor","user_email":"editor@example.test","roles":["{second_role}"],"user_registered":"2020-01-01 00:00:00"}}]"#
        )
    }

    #[test]
    fn blocks_deleting_or_demoting_the_last_administrator() {
        let executor = UserMockSsh {
            users_json: user_json(false),
            multisite: false,
            mutations: Mutex::new(Vec::new()),
        };
        let delete_error = delete(
            &executor,
            &stored(),
            None,
            &WordPressUserDeleteInput {
                user_id: 1,
                reassign_to: Some(2),
                delete_content: false,
            },
        )
        .unwrap_err();
        assert!(delete_error.user_message.contains("laatste Administrator"));
        let update_error = update(
            &executor,
            &stored(),
            None,
            &WordPressUserUpdateInput {
                user_id: 1,
                display_name: "Admin".into(),
                email: "admin@example.test".into(),
                role: Some("editor".into()),
            },
        )
        .unwrap_err();
        assert!(update_error.user_message.contains("laatste Administrator"));
        assert!(executor.mutations.lock().unwrap().is_empty());
    }

    #[test]
    fn multisite_delete_stays_scoped_to_current_site() {
        let executor = UserMockSsh {
            users_json: user_json(true),
            multisite: true,
            mutations: Mutex::new(Vec::new()),
        };
        let result = delete(
            &executor,
            &stored(),
            None,
            &WordPressUserDeleteInput {
                user_id: 1,
                reassign_to: Some(2),
                delete_content: false,
            },
        )
        .unwrap();
        assert!(result.multisite);
        let commands = executor.mutations.lock().unwrap();
        assert_eq!(commands.len(), 1);
        assert!(commands[0].contains("user delete 1 --reassign=2 --yes"));
        assert!(!commands[0].contains("--network"));
    }

    #[test]
    fn role_must_come_from_current_wordpress_site() {
        let executor = UserMockSsh {
            users_json: user_json(true),
            multisite: false,
            mutations: Mutex::new(Vec::new()),
        };
        let error = update(
            &executor,
            &stored(),
            None,
            &WordPressUserUpdateInput {
                user_id: 2,
                display_name: "Editor".into(),
                email: "editor@example.test".into(),
                role: Some("invented_role".into()),
            },
        )
        .unwrap_err();
        assert!(error.user_message.contains("bestaat niet"));
        assert!(executor.mutations.lock().unwrap().is_empty());
    }

    #[test]
    fn updates_display_name_email_and_allowed_role() {
        let executor = UserMockSsh {
            users_json: user_json(true),
            multisite: false,
            mutations: Mutex::new(Vec::new()),
        };
        update(
            &executor,
            &stored(),
            None,
            &WordPressUserUpdateInput {
                user_id: 2,
                display_name: "Editor O'Brien".into(),
                email: "new-editor@example.test".into(),
                role: Some("editor".into()),
            },
        )
        .unwrap();
        let commands = executor.mutations.lock().unwrap();
        assert_eq!(commands.len(), 1);
        assert!(commands[0].contains("user update 2"));
        assert!(commands[0].contains("--user_email='new-editor@example.test'"));
        assert!(commands[0].contains("--role='editor'"));
        assert!(commands[0].contains("Editor O'\"'\"'Brien"));
    }

    #[test]
    fn rejects_unknown_reassignment_target() {
        let executor = UserMockSsh {
            users_json: user_json(true),
            multisite: false,
            mutations: Mutex::new(Vec::new()),
        };
        let error = delete(
            &executor,
            &stored(),
            None,
            &WordPressUserDeleteInput {
                user_id: 1,
                reassign_to: Some(999),
                delete_content: false,
            },
        )
        .unwrap_err();
        assert!(error.user_message.contains("bestaat niet"));
        assert!(executor.mutations.lock().unwrap().is_empty());
    }

    #[test]
    fn explicit_content_deletion_omits_reassignment() {
        let executor = UserMockSsh {
            users_json: user_json(true),
            multisite: false,
            mutations: Mutex::new(Vec::new()),
        };
        delete(
            &executor,
            &stored(),
            None,
            &WordPressUserDeleteInput {
                user_id: 1,
                reassign_to: None,
                delete_content: true,
            },
        )
        .unwrap();
        let commands = executor.mutations.lock().unwrap();
        assert!(commands[0].contains("user delete 1 --yes"));
        assert!(!commands[0].contains("--reassign"));
    }

    #[test]
    fn deletion_requires_one_explicit_content_choice() {
        let executor = UserMockSsh {
            users_json: user_json(true),
            multisite: false,
            mutations: Mutex::new(Vec::new()),
        };
        assert!(
            delete(
                &executor,
                &stored(),
                None,
                &WordPressUserDeleteInput {
                    user_id: 1,
                    reassign_to: None,
                    delete_content: false,
                }
            )
            .is_err()
        );
        assert!(
            delete(
                &executor,
                &stored(),
                None,
                &WordPressUserDeleteInput {
                    user_id: 1,
                    reassign_to: Some(2),
                    delete_content: true,
                }
            )
            .is_err()
        );
        assert!(executor.mutations.lock().unwrap().is_empty());
    }
}
