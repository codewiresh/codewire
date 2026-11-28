//! The cloud store's `cw secrets` commands: personal, organization and
//! project keys, and secret projects.

use super::*;

pub(crate) async fn handle_platform_secrets_command(
    globals: &Globals,
    command: SecretOperation,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = SecretClient::new(&platform)?;
    let organizations = organization_client(&platform)?;

    match command {
        SecretOperation::User(command) => {
            handle_user_secret_command(&client, command).await?;
        }
        SecretOperation::Organization(command) => {
            let orgs = organizations.list_orgs().await.context("list orgs")?;
            let org_id = resolve_org_id(&platform, &orgs, globals.org.as_deref())?;
            handle_org_secret_command(&client, &org_id, command).await?;
        }
        SecretOperation::Preview(args) => {
            let intent = load_secret_preview_intent(&args.file)?;
            validate_secret_preview_placement(
                &intent,
                super::storage_placement::StoragePlacement::Platform,
            )?;
            let orgs = organizations.list_orgs().await.context("list orgs")?;
            let org_id = resolve_org_id(&platform, &orgs, globals.org.as_deref())?;
            let secret_project_id = if let Some(project_name) = intent.project.as_deref() {
                Some(
                    load_secret_project_by_name(&client, &org_id, project_name)
                        .await?
                        .id,
                )
            } else {
                None
            };
            let secrets = client
                .preview_workload_secret_resolution(
                    &org_id,
                    intent.organization,
                    secret_project_id.as_deref(),
                    intent.user.is_some(),
                    intent.explicit_environment_keys,
                )
                .await
                .context("preview platform workload-secret resolution")?;
            print_secret_resolution("platform", &secrets, args.output)?;
        }
        SecretOperation::Project { name, command } => {
            let orgs = organizations.list_orgs().await.context("list orgs")?;
            let org_id = resolve_org_id(&platform, &orgs, globals.org.as_deref())?;
            handle_project_secret_command(&client, &org_id, &name, command).await?;
        }
        SecretOperation::Projects(command) => {
            let orgs = organizations.list_orgs().await.context("list orgs")?;
            let org_id = resolve_org_id(&platform, &orgs, globals.org.as_deref())?;
            match command {
                SecretProjectCommand::Create(args) => {
                    let name = trimmed_required(
                        args.name
                            .as_deref()
                            .context("secret project name is required")?,
                        "secret project name",
                    )?;
                    let created = client
                        .create_secret_project(
                            &org_id,
                            &CreateSecretProjectRequest {
                                name: name.to_string(),
                            },
                        )
                        .await;
                    let project = cloud_project_created(created, name)?;
                    eprintln!(
                        "Secret project {:?} created. (id: {})",
                        project.name, project.id
                    );
                }
                SecretProjectCommand::List(args) => {
                    let projects = client
                        .list_secret_projects(&org_id)
                        .await
                        .context("list secret projects")?;
                    print_secret_project_list(&projects, args.output)?;
                }
                SecretProjectCommand::Delete(args) => {
                    let project_name = trimmed_required(&args.name, "secret project")?;
                    let project =
                        load_secret_project_by_name(&client, &org_id, project_name).await?;
                    let target =
                        format!("cloud secret project {:?} ({})", project.name, project.id);
                    if !confirm_secret_project_delete(&target, args.yes)? {
                        eprintln!("Canceled.");
                        return Ok(());
                    }
                    client
                        .delete_secret_project(&org_id, &project.id)
                        .await
                        .context("delete secret project")?;
                    eprintln!("Secret project {project_name:?} deleted.");
                }
            }
        }
    }

    Ok(())
}

async fn handle_project_secret_command(
    client: &SecretClient,
    org_id: &str,
    project_name: &str,
    command: ScopedSecretCommand,
) -> anyhow::Result<()> {
    if let ScopedSecretCommand::Set(args) = &command
        && args.new_project
    {
        let key = args.key.as_deref().context("secret key is required")?;
        refuse_binding_in_new_project(args, StoragePlacement::Platform, project_name)?;
        let value = prompt_platform_workload_secret_value()?;
        let created = client
            .create_secret_project(
                org_id,
                &CreateSecretProjectRequest {
                    name: project_name.to_owned(),
                },
            )
            .await;
        let project = cloud_project_created(created, project_name)?;
        client.set_project_secret(org_id, &project.id, key, &value).await.with_context(|| format!("secret project {project_name:?} created; setting its first secret failed, inspect the project before retrying"))?;
        eprintln!("Created secret project {project_name:?} and set {key}.");
        return Ok(());
    }
    let project = load_secret_project_by_name(client, org_id, project_name).await?;
    match command {
        ScopedSecretCommand::List(args) => {
            let secrets = client
                .list_project_secrets(org_id, &project.id)
                .await
                .context("list project secrets")?;
            print_key_list(
                &secrets,
                &format!("No secrets in project {project_name:?}."),
                &args,
            )?;
        }
        ScopedSecretCommand::Set(args) => {
            let mut keys = set::CloudKeys::project(client, org_id, &project.id, project_name);
            set::set_key(&mut keys, &args).await?;
        }
        ScopedSecretCommand::Delete(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            let deleted = client.delete_project_secret(org_id, &project.id, key).await;
            cloud_deleted(deleted, SecretScope::Project(project_name), key)?;
            eprintln!("Secret {key} deleted from project {project_name:?}.");
        }
        ScopedSecretCommand::Rename(args) => {
            let old_key = trimmed_required(&args.old_key, "old secret key")?;
            let new_key = trimmed_required(&args.new_key, "new secret key")?;
            let renamed = client
                .rename_project_secret(org_id, &project.id, old_key, new_key)
                .await;
            cloud_renamed(
                renamed,
                SecretScope::Project(project_name),
                old_key,
                new_key,
            )?;
            eprintln!("Secret {old_key} renamed to {new_key} in project {project_name:?}.");
        }
    }
    Ok(())
}

async fn handle_user_secret_command(
    client: &SecretClient,
    command: ScopedSecretCommand,
) -> anyhow::Result<()> {
    match command {
        ScopedSecretCommand::List(args) => {
            let secrets = client
                .list_user_secrets()
                .await
                .context("list user secrets")?;
            print_key_list(&secrets, "No user secrets found.", &args)?;
        }
        ScopedSecretCommand::Set(args) => {
            set::set_key(&mut set::CloudKeys::user(client), &args).await?;
        }
        ScopedSecretCommand::Delete(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            let deleted = client.delete_user_secret(key).await;
            cloud_deleted(deleted, SecretScope::User, key)?;
            eprintln!("Secret {key} deleted.");
        }
        ScopedSecretCommand::Rename(args) => {
            let old_key = trimmed_required(&args.old_key, "old secret key")?;
            let new_key = trimmed_required(&args.new_key, "new secret key")?;
            let renamed = client.rename_user_secret(old_key, new_key).await;
            cloud_renamed(renamed, SecretScope::User, old_key, new_key)?;
            eprintln!("Secret {old_key} renamed to {new_key}.");
        }
    }

    Ok(())
}

async fn handle_org_secret_command(
    client: &SecretClient,
    org_id: &str,
    command: ScopedSecretCommand,
) -> anyhow::Result<()> {
    match command {
        ScopedSecretCommand::List(args) => {
            let secrets = client
                .list_org_secrets(org_id)
                .await
                .context("list org secrets")?;
            print_key_list(&secrets, "No organization secrets found.", &args)?;
        }
        ScopedSecretCommand::Set(args) => {
            set::set_key(&mut set::CloudKeys::organization(client, org_id), &args).await?;
        }
        ScopedSecretCommand::Delete(args) => {
            let key = trimmed_required(&args.key, "secret key")?;
            let deleted = client.delete_org_secret(org_id, key).await;
            cloud_deleted(deleted, SecretScope::Organization, key)?;
            eprintln!("Secret {key} deleted.");
        }
        ScopedSecretCommand::Rename(args) => {
            let old_key = trimmed_required(&args.old_key, "old secret key")?;
            let new_key = trimmed_required(&args.new_key, "new secret key")?;
            let renamed = client.rename_org_secret(org_id, old_key, new_key).await;
            cloud_renamed(renamed, SecretScope::Organization, old_key, new_key)?;
            eprintln!("Secret {old_key} renamed to {new_key}.");
        }
    }

    Ok(())
}

pub(crate) async fn load_secret_project_by_name(
    client: &SecretClient,
    org_id: &str,
    project_name: &str,
) -> anyhow::Result<SecretProject> {
    let projects = client
        .list_secret_projects(org_id)
        .await
        .context("list secret projects")?;
    resolve_platform_secret_project(&projects, project_name).cloned()
}

fn resolve_platform_secret_project<'a>(
    projects: &'a [SecretProject],
    selector: &str,
) -> anyhow::Result<&'a SecretProject> {
    let selector = project_selector_for_placement(
        selector,
        super::storage_placement::StoragePlacement::Platform,
    )?;
    let mut matches = projects
        .iter()
        .filter(|project| match selector.strip_prefix("id:") {
            Some(id) => project.id == id,
            None => project.name.eq_ignore_ascii_case(selector),
        });
    let cloud = super::storage_placement::StoragePlacement::Platform;
    let project = matches
        .next()
        .ok_or_else(|| no_such_project(cloud, selector))?;
    if matches.next().is_some() {
        return Err(ambiguous_project(cloud, selector));
    }
    Ok(project)
}
