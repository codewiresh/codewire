use serde::Serialize;
use std::path::Path;

use super::storage_placement::{
    StoragePlacement, require_reference_placement, resolve_storage_placement,
};
use super::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use codewire_local_credentials::{
    LocalCredentialClient, LocalSecretProject, WorkloadSecretMetadata,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use codewire_protected_store::ProtectedValue;
use codewire_workload_secrets::{
    MAX_WORKLOAD_SECRET_VALUE_BYTES, ResolvedWorkloadSecretMetadata, WorkloadSecretSource,
    validate_workload_secret_value,
};
use std::io::{BufRead as _, Read as _};
use zeroize::Zeroizing;

#[derive(Debug)]
pub(crate) enum SecretOperation {
    User(ScopedSecretCommand),
    Organization(ScopedSecretCommand),
    Project {
        name: String,
        command: ScopedSecretCommand,
    },
    Projects(SecretProjectCommand),
    Preview(SecretPreviewArgs),
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct SecretResolutionView {
    pub(crate) placement: &'static str,
    pub(crate) key: String,
    pub(crate) source: &'static str,
    pub(crate) overridden_sources: Vec<&'static str>,
}

#[derive(Debug)]
pub(crate) struct SecretPreviewIntent {
    pub(crate) organization: bool,
    pub(crate) project: Option<String>,
    pub(crate) user: Option<StoragePlacement>,
    pub(crate) explicit_environment_keys: BTreeSet<String>,
}

pub(crate) async fn handle_secrets_command(
    globals: &Globals,
    mut args: SecretsArgs,
) -> anyhow::Result<()> {
    let local = globals.placement == Some(EnvironmentPlacement::Local);
    let platform = globals.placement == Some(EnvironmentPlacement::Platform);
    let addition = matches!(
        &args.command,
        SecretsCommand::Set(_)
            | SecretsCommand::Projects {
                command: SecretProjectCommand::Create(_)
            }
    );
    if addition {
        let missing = match &args.command {
            SecretsCommand::Set(set) => {
                set.key.is_none() || (!args.user && !args.organization && args.project.is_none())
            }
            SecretsCommand::Projects {
                command: SecretProjectCommand::Create(create),
            } => create.name.is_none(),
            _ => false,
        };
        if missing {
            super::guided::require_available(
                OutputFormat::Text,
                "supply KEY and one of --project NAME, --user, --organization; project creation needs NAME",
            )?;
        }
        let placement = resolve_storage_placement(local, platform, false)?;
        complete_secret_metadata(
            globals,
            &mut args,
            placement,
            missing || globals.placement.is_none(),
        )
        .await?;
        let operation = resolve_secret_operation(args)?;
        validate_secret_operation_placement(&operation, placement)?;
        return dispatch_secrets(globals, operation, placement).await;
    }
    let operation = resolve_secret_operation(args)?;
    let placement = resolve_storage_placement(local, platform, secret_operation_json(&operation))?;
    validate_secret_operation_placement(&operation, placement)?;
    dispatch_secrets(globals, operation, placement).await
}

pub(super) async fn dispatch_secrets(
    globals: &Globals,
    operation: SecretOperation,
    placement: StoragePlacement,
) -> anyhow::Result<()> {
    if placement == StoragePlacement::Local && matches!(operation, SecretOperation::Organization(_))
    {
        anyhow::bail!("organization workload secrets are unsupported locally; use --cloud");
    }
    match placement {
        StoragePlacement::Platform => handle_platform_secrets_command(globals, operation).await,
        StoragePlacement::Local => handle_local_secrets_command(operation).await,
    }
}

async fn complete_secret_metadata(
    globals: &Globals,
    args: &mut SecretsArgs,
    placement: StoragePlacement,
    guided: bool,
) -> anyhow::Result<()> {
    use super::guided::{self, Choice};
    let SecretsCommand::Set(set) = &mut args.command else {
        if let SecretsCommand::Projects {
            command: SecretProjectCommand::Create(create),
        } = &mut args.command
            && create.name.is_none()
        {
            create.name = Some(guided::text("Secret project name", None, |name| {
                parse_secret_project_name(name).map(|_| ())
            })?);
        }
        return Ok(());
    };
    anyhow::ensure!(
        !(args.organization && placement == StoragePlacement::Local),
        "organization workload secrets are unsupported locally; use --cloud"
    );
    set.guided = guided;
    if args.project.is_none() && !args.user && !args.organization {
        let mut scopes = vec![
            Choice::new(
                "A project",
                "Select the project when configuring an environment",
            ),
            Choice::new("Your account", "User-scoped secret"),
        ];
        if placement == StoragePlacement::Platform {
            scopes.push(Choice::new("Organization", "Organization-scoped secret"));
        }
        match guided::choose("Where should this secret live?", &scopes)? {
            0 => {
                let projects = secret_project_choices(globals, placement).await?;
                let mut choices = projects
                    .iter()
                    .map(|(name, _)| Choice::new(name, "Existing project"))
                    .collect::<Vec<_>>();
                choices.push(Choice::new(
                    "Create a project",
                    "Create it before saving the first secret",
                ));
                let index = guided::choose("Choose a secret project", &choices)?;
                if let Some((_, selector)) = projects.get(index) {
                    args.project = Some(selector.clone());
                } else {
                    args.project = Some(guided::text("New secret project name", None, |name| {
                        parse_secret_project_name(name).map(|_| ())
                    })?);
                    set.new_project = true;
                }
            }
            1 => args.user = true,
            _ => args.organization = true,
        }
    }
    if set.key.is_none() {
        set.key = Some(guided::text("Secret key", None, |key| {
            parse_secret_key(key).map(|_| ())
        })?);
    }
    Ok(())
}

pub(super) async fn secret_project_choices(
    globals: &Globals,
    placement: StoragePlacement,
) -> anyhow::Result<Vec<(String, String)>> {
    if placement == StoragePlacement::Local {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let mut client = connect_local_credential_authority().await?;
            return Ok(client
                .list_secret_projects()
                .await?
                .into_iter()
                .map(|project| (project.name, format!("id:{}", project.id)))
                .collect());
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("local secret storage is unavailable on this host");
    }
    let paths = ResolvePaths::from_env(&OsEnv)?;
    let platform = resolve_platform(globals, &paths, &OsEnv)?;
    let orgs = organization_client(&platform)?.list_orgs().await?;
    let org = resolve_org_id(&platform, &orgs, globals.org.as_deref())?;
    let client = SecretClient::new(&platform)?;
    Ok(client
        .list_secret_projects(&org)
        .await?
        .into_iter()
        .map(|project| (project.name, format!("id:{}", project.id)))
        .collect())
}

pub(crate) fn parse_secret_project_name(value: &str) -> Result<String, String> {
    let reference =
        codewire_project::StorageReference::project(value).map_err(|error| error.to_string())?;
    if reference.placement.is_some() || reference.selector.starts_with("id:") {
        return Err("project creation requires a bare project name".to_owned());
    }
    Ok(value.to_owned())
}

pub(crate) fn parse_secret_project_reference(value: &str) -> Result<String, String> {
    codewire_project::StorageReference::project(value).map_err(|error| error.to_string())?;
    Ok(value.to_owned())
}

pub(crate) fn project_selector_for_placement(
    value: &str,
    placement: StoragePlacement,
) -> anyhow::Result<&str> {
    let selector = require_reference_placement(
        codewire_project::StorageReference::project(value)?,
        placement,
    )?;
    if let Some(id) = selector.strip_prefix("id:") {
        let parsed = uuid::Uuid::parse_str(id).context("invalid secret project ID")?;
        anyhow::ensure!(
            !parsed.is_nil() && parsed.to_string() == id,
            "secret project ID must be canonical and non-nil"
        );
    }
    Ok(selector)
}

fn validate_secret_operation_placement(
    operation: &SecretOperation,
    placement: StoragePlacement,
) -> anyhow::Result<()> {
    match operation {
        SecretOperation::Project { name, .. } => {
            project_selector_for_placement(name, placement)?;
        }
        SecretOperation::Projects(SecretProjectCommand::Delete(args)) => {
            project_selector_for_placement(&args.name, placement)?;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn parse_secret_key(value: &str) -> Result<String, String> {
    codewire_workload_secrets::validate_workload_secret_key(value)
        .map_err(|_| "invalid secret key: use a nonempty environment-variable name".to_owned())?;
    Ok(value.to_owned())
}

fn resolve_secret_operation(args: SecretsArgs) -> anyhow::Result<SecretOperation> {
    let scope_count = usize::from(args.project.is_some())
        + usize::from(args.user)
        + usize::from(args.organization);
    let command = match args.command {
        SecretsCommand::Preview(preview) => {
            anyhow::ensure!(
                scope_count == 0,
                "preview reads source selectors from --file; scope flags do not apply"
            );
            return Ok(SecretOperation::Preview(preview));
        }
        SecretsCommand::Projects { command } => {
            anyhow::ensure!(
                scope_count == 0,
                "projects commands take their own project name; scope flags do not apply"
            );
            return Ok(SecretOperation::Projects(command));
        }
        SecretsCommand::List(args) => ScopedSecretCommand::List(args),
        SecretsCommand::Set(args) => ScopedSecretCommand::Set(args),
        SecretsCommand::Delete(args) => ScopedSecretCommand::Delete(args),
        SecretsCommand::Rename(args) => ScopedSecretCommand::Rename(args),
    };
    if let ScopedSecretCommand::Set(args) = &command {
        anyhow::ensure!(args.key.is_some(), "secret key is required; supply KEY");
    }
    anyhow::ensure!(
        scope_count == 1,
        "key operations require exactly one of --project=NAME, --user, or --organization; no project is inferred"
    );
    if let Some(name) = args.project {
        Ok(SecretOperation::Project { name, command })
    } else if args.user {
        Ok(SecretOperation::User(command))
    } else {
        Ok(SecretOperation::Organization(command))
    }
}

fn secret_operation_json(operation: &SecretOperation) -> bool {
    match operation {
        SecretOperation::Preview(args) => args.output == OutputFormat::Json,
        SecretOperation::Projects(SecretProjectCommand::List(args))
        | SecretOperation::User(ScopedSecretCommand::List(args))
        | SecretOperation::Organization(ScopedSecretCommand::List(args))
        | SecretOperation::Project {
            command: ScopedSecretCommand::List(args),
            ..
        } => args.output == OutputFormat::Json,
        _ => false,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn handle_local_secrets_command(_command: SecretOperation) -> anyhow::Result<()> {
    anyhow::bail!("local workload-secret management is not available on this operating system")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_local_secrets_command(command: SecretOperation) -> anyhow::Result<()> {
    let mut client = connect_local_credential_authority().await?;
    match command {
        SecretOperation::Preview(args) => {
            let intent = load_secret_preview_intent(&args.file)?;
            validate_secret_preview_placement(&intent, StoragePlacement::Local)?;
            let mut source_keys = Vec::new();
            if let Some(selector) = &intent.project {
                let project = resolve_local_project_by_name(&mut client, selector).await?;
                for metadata in client.list_project_workload_secrets(project.id).await? {
                    source_keys.push((WorkloadSecretSource::Project, metadata.key));
                }
            }
            if intent.user.is_some() {
                for metadata in client.list_user_workload_secrets().await? {
                    source_keys.push((WorkloadSecretSource::User, metadata.key));
                }
            }
            source_keys.extend(
                intent
                    .explicit_environment_keys
                    .into_iter()
                    .map(|key| (WorkloadSecretSource::ExplicitEnvironment, key)),
            );
            let secrets = codewire_workload_secrets::resolve_workload_secret_metadata(
                source_keys
                    .iter()
                    .map(|(source, key)| (*source, key.as_str())),
            )
            .context("preview local workload-secret resolution")?;
            print_secret_resolution("local", &secrets, args.output)
        }
        SecretOperation::Organization(_) => {
            anyhow::bail!("organization workload secrets are unsupported locally")
        }
        SecretOperation::User(command) => local_user_command(&mut client, command).await,
        SecretOperation::Project { name, command } => {
            local_project_key_command(&mut client, &name, command).await
        }
        SecretOperation::Projects(command) => local_project_command(&mut client, command).await,
    }
}

pub(crate) fn load_secret_preview_intent(path: &Path) -> anyhow::Result<SecretPreviewIntent> {
    let file = fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut data = String::new();
    file.take((codewire_project::MAX_PROJECT_DOCUMENT_BYTES + 1) as u64)
        .read_to_string(&mut data)
        .with_context(|| format!("read {}", path.display()))?;
    let document = codewire_project::parse_project_yaml(&data)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(SecretPreviewIntent {
        organization: document.spec.secrets.organization,
        project: (!document.spec.secrets.project.is_empty())
            .then_some(document.spec.secrets.project),
        user: document.spec.secrets.user,
        explicit_environment_keys: document.spec.environment.into_keys().collect(),
    })
}

pub(crate) fn validate_secret_preview_placement(
    intent: &SecretPreviewIntent,
    placement: StoragePlacement,
) -> anyhow::Result<()> {
    if let Some(project) = &intent.project {
        project_selector_for_placement(project, placement)?;
    }
    anyhow::ensure!(
        intent.user.is_none_or(|origin| origin == placement),
        "user secret origin conflicts with selected storage; cross-origin preview is not supported by this adapter"
    );
    anyhow::ensure!(
        placement != StoragePlacement::Local || !intent.organization,
        "organization workload secrets are unsupported in local preview; use --cloud"
    );
    Ok(())
}

pub(crate) fn print_secret_resolution(
    placement: &'static str,
    secrets: &[ResolvedWorkloadSecretMetadata],
    output: OutputFormat,
) -> anyhow::Result<()> {
    let rows = secrets
        .iter()
        .map(|secret| SecretResolutionView {
            placement,
            key: secret.key.clone(),
            source: workload_secret_source_label(secret.source),
            overridden_sources: secret
                .overridden_sources
                .iter()
                .copied()
                .map(workload_secret_source_label)
                .collect(),
        })
        .collect::<Vec<_>>();
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
        OutputFormat::Text if rows.is_empty() => println!("No workload secrets selected."),
        OutputFormat::Text => {
            println!(
                "{:<10} {:<32} {:<24} OVERRIDDEN",
                "PLACEMENT", "KEY", "SOURCE"
            );
            for row in rows {
                println!(
                    "{:<10} {:<32} {:<24} {}",
                    row.placement,
                    row.key,
                    row.source,
                    if row.overridden_sources.is_empty() {
                        "-".to_string()
                    } else {
                        row.overridden_sources.join(",")
                    }
                );
            }
        }
    }
    Ok(())
}

fn workload_secret_source_label(source: WorkloadSecretSource) -> &'static str {
    match source {
        WorkloadSecretSource::Organization => "organization",
        WorkloadSecretSource::Project => "project",
        WorkloadSecretSource::User => "user",
        WorkloadSecretSource::ExplicitEnvironment => "explicit_environment",
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn local_user_command(
    client: &mut LocalCredentialClient,
    command: ScopedSecretCommand,
) -> anyhow::Result<()> {
    match command {
        ScopedSecretCommand::List(args) => {
            let secrets = client
                .list_user_workload_secrets()
                .await
                .context("list local user secrets")?;
            print_local_secret_metadata(&secrets, "No local user secrets found.", args.output)
        }
        ScopedSecretCommand::Set(args) => {
            let key = trimmed_required(
                args.key.as_deref().context("secret key is required")?,
                "secret key",
            )?
            .to_owned();
            if args.guided
                && client
                    .list_user_workload_secrets()
                    .await?
                    .iter()
                    .any(|existing| existing.key == key)
                && !super::guided::confirm(&format!("Replace the existing value for {key}?"))?
            {
                return Ok(());
            }
            let value = prompt_workload_secret_value()?;
            client
                .set_user_workload_secret(key.clone(), value)
                .await
                .context("set local user secret")?;
            eprintln!("Local user secret {key} set.");
            Ok(())
        }
        ScopedSecretCommand::Delete(args) => {
            let key = trimmed_required(&args.key, "secret key")?.to_owned();
            client
                .delete_user_workload_secret(key.clone())
                .await
                .context("delete local user secret")?;
            eprintln!("Local user secret {key} deleted.");
            Ok(())
        }
        ScopedSecretCommand::Rename(args) => {
            let key = trimmed_required(&args.old_key, "old secret key")?.to_owned();
            let new_key = trimmed_required(&args.new_key, "new secret key")?.to_owned();
            client
                .rename_user_workload_secret(key.clone(), new_key.clone())
                .await
                .context("rename local user secret")?;
            eprintln!("Local user secret {key} renamed to {new_key}.");
            Ok(())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn local_project_command(
    client: &mut LocalCredentialClient,
    command: SecretProjectCommand,
) -> anyhow::Result<()> {
    match command {
        SecretProjectCommand::Create(args) => {
            let name = trimmed_required(
                args.name
                    .as_deref()
                    .context("secret project name is required")?,
                "secret project name",
            )?
            .to_owned();
            let project = client
                .create_secret_project(name)
                .await
                .context("create local secret project")?;
            eprintln!(
                "Local secret project {:?} created ({}).",
                project.name, project.id
            );
            Ok(())
        }
        SecretProjectCommand::List(args) => {
            let projects = client
                .list_secret_projects()
                .await
                .context("list local secret projects")?;
            print_local_secret_projects(&projects, args.output)
        }
        SecretProjectCommand::Delete(args) => {
            let project = resolve_local_project_by_name(client, &args.name).await?;
            let target = format!("local secret project {:?} ({})", project.name, project.id);
            if !confirm_secret_project_delete(&target, args.yes)? {
                eprintln!("Canceled.");
                return Ok(());
            }
            client
                .delete_secret_project(project.id)
                .await
                .context("delete local secret project")?;
            eprintln!("Local secret project {:?} deleted.", project.name);
            Ok(())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn local_project_key_command(
    client: &mut LocalCredentialClient,
    project_name: &str,
    command: ScopedSecretCommand,
) -> anyhow::Result<()> {
    if let ScopedSecretCommand::Set(args) = &command
        && args.new_project
    {
        let key = args.key.as_deref().context("secret key is required")?;
        let value = prompt_workload_secret_value()?;
        let project = client
            .create_secret_project(project_name.to_owned())
            .await
            .context("create secret project")?;
        client.set_project_workload_secret(project.id, key.to_owned(), value).await.with_context(|| format!("secret project {project_name:?} created; setting its first secret failed, inspect the project before retrying"))?;
        eprintln!("Created secret project {project_name:?} and set {key}.");
        return Ok(());
    }
    let project = resolve_local_project_by_name(client, project_name).await?;
    match command {
        ScopedSecretCommand::List(args) => {
            let secrets = client
                .list_project_workload_secrets(project.id)
                .await
                .context("list local project secrets")?;
            print_local_secret_metadata(
                &secrets,
                &format!("No local secrets in project {:?}.", project.name),
                args.output,
            )
        }
        ScopedSecretCommand::Set(args) => {
            let key = trimmed_required(
                args.key.as_deref().context("secret key is required")?,
                "secret key",
            )?
            .to_owned();
            if args.guided
                && client
                    .list_project_workload_secrets(project.id)
                    .await?
                    .iter()
                    .any(|existing| existing.key == key)
                && !super::guided::confirm(&format!("Replace the existing value for {key}?"))?
            {
                return Ok(());
            }
            let value = prompt_workload_secret_value()?;
            client
                .set_project_workload_secret(project.id, key.clone(), value)
                .await
                .context("set local project secret")?;
            eprintln!("Local secret {key} set in project {:?}.", project.name);
            Ok(())
        }
        ScopedSecretCommand::Delete(args) => {
            let key = trimmed_required(&args.key, "secret key")?.to_owned();
            client
                .delete_project_workload_secret(project.id, key.clone())
                .await
                .context("delete local project secret")?;
            eprintln!(
                "Local secret {key} deleted from project {:?}.",
                project.name
            );
            Ok(())
        }
        ScopedSecretCommand::Rename(args) => {
            let key = trimmed_required(&args.old_key, "old secret key")?.to_owned();
            let new_key = trimmed_required(&args.new_key, "new secret key")?.to_owned();
            client
                .rename_project_workload_secret(project.id, key.clone(), new_key.clone())
                .await
                .context("rename local project secret")?;
            eprintln!(
                "Local secret {key} renamed to {new_key} in project {:?}.",
                project.name
            );
            Ok(())
        }
    }
}

pub(crate) fn confirm_secret_project_delete(target: &str, yes: bool) -> anyhow::Result<bool> {
    if yes {
        eprintln!("Deleting {target} and all its keys.");
        return Ok(true);
    }
    anyhow::ensure!(
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "project deletion requires --yes when noninteractive"
    );
    read_secret_project_delete_confirmation(
        target,
        std::io::stdin().lock(),
        std::io::stderr().lock(),
    )
}

fn read_secret_project_delete_confirmation(
    target: &str,
    reader: impl std::io::BufRead,
    mut writer: impl std::io::Write,
) -> anyhow::Result<bool> {
    write!(writer, "Delete {target} and all its keys? [y/N]: ")
        .context("write project deletion confirmation")?;
    writer
        .flush()
        .context("flush project deletion confirmation")?;
    let mut input = String::new();
    let count = reader
        .take(65)
        .read_line(&mut input)
        .context("read project deletion confirmation")?;
    Ok(count > 0 && count < 65 && matches!(input.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn resolve_local_project_by_name(
    client: &mut LocalCredentialClient,
    name: &str,
) -> anyhow::Result<LocalSecretProject> {
    let projects = client
        .list_secret_projects()
        .await
        .context("list local secret projects")?;
    Ok(resolve_local_project(&projects, name)?.clone())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_local_project<'a>(
    projects: &'a [LocalSecretProject],
    name: &str,
) -> anyhow::Result<&'a LocalSecretProject> {
    let selector = project_selector_for_placement(name, StoragePlacement::Local)?;
    let mut matches = projects
        .iter()
        .filter(|project| match selector.strip_prefix("id:") {
            Some(id) => project.id.to_string() == id,
            None => project.name.eq_ignore_ascii_case(selector),
        });
    let project = matches
        .next()
        .context("local secret project was not found")?;
    anyhow::ensure!(
        matches.next().is_none(),
        "local secret project name is ambiguous; select an exact id"
    );
    Ok(project)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_local_secret_metadata(
    secrets: &[WorkloadSecretMetadata],
    empty: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let secrets = secrets
        .iter()
        .map(|secret| SecretMetadata {
            key: secret.key.clone(),
            created_at: format_unix_millis(secret.created_at_unix_ms),
            updated_at: format_unix_millis(secret.updated_at_unix_ms),
        })
        .collect::<Vec<_>>();
    print_secret_metadata_list(&secrets, empty, output)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_local_secret_projects(
    projects: &[LocalSecretProject],
    output: OutputFormat,
) -> anyhow::Result<()> {
    let projects = projects
        .iter()
        .map(|project| SecretProject {
            id: project.id.to_string(),
            org_id: String::new(),
            name: project.name.clone(),
            secret_count: i64::try_from(project.secret_count).unwrap_or(i64::MAX),
            created_at: format_unix_millis(project.created_at_unix_ms),
        })
        .collect::<Vec<_>>();
    print_secret_project_list(&projects, output)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn format_unix_millis(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prompt_workload_secret_value() -> anyhow::Result<ProtectedValue> {
    let mut value = prompt_workload_secret_bytes()?;
    ProtectedValue::new(std::mem::take(&mut *value)).context("invalid workload-secret value")
}

pub(crate) fn prompt_platform_workload_secret_value() -> anyhow::Result<Zeroizing<String>> {
    let mut bytes = prompt_workload_secret_bytes()?;
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let _bytes = Zeroizing::new(error.into_bytes());
            anyhow::bail!("workload-secret value must be valid UTF-8")
        }
    }
}

fn prompt_workload_secret_bytes() -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        let value = super::credential_input::read_hidden_terminal_bytes(
            "Value: ",
            MAX_WORKLOAD_SECRET_VALUE_BYTES,
        );
        eprintln!();
        let value = value?;
        validate_workload_secret_value(&value)?;
        Ok(value)
    } else {
        read_workload_secret_bytes(std::io::stdin().lock(), false)
    }
}

fn read_workload_secret_bytes<R: std::io::BufRead>(
    reader: R,
    single_line: bool,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let limit =
        u64::try_from(MAX_WORKLOAD_SECRET_VALUE_BYTES + 3).expect("workload-secret value limit");
    let mut reader = reader.take(limit);
    if single_line {
        reader
            .read_until(b'\n', &mut bytes)
            .context("read workload-secret value")?;
    } else {
        reader
            .read_to_end(&mut bytes)
            .context("read workload-secret value")?;
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    validate_workload_secret_value(&bytes).map_err(|_| {
        anyhow::anyhow!(
            "workload-secret value must be non-empty UTF-8 without NUL bytes and at most {MAX_WORKLOAD_SECRET_VALUE_BYTES} bytes"
        )
    })?;
    Ok(bytes)
}

pub(super) async fn choose_secret_project_reference(
    globals: &Globals,
    placement: StoragePlacement,
) -> anyhow::Result<String> {
    use super::guided::{self, Choice};
    let projects = secret_project_choices(globals, placement).await?;
    let mut choices = projects
        .iter()
        .map(|(name, _)| Choice::new(name, "Secret project"))
        .collect::<Vec<_>>();
    choices.push(Choice::new(
        "Create a secret project",
        "Add its keys with cw secrets set",
    ));
    let index = guided::choose("Choose a secret project", &choices)?;
    let selector = if let Some((_, selector)) = projects.get(index) {
        selector.clone()
    } else {
        let name = guided::text("Secret project name", None, |name| {
            parse_secret_project_name(name).map(|_| ())
        })?;
        anyhow::ensure!(
            guided::confirm(&format!(
                "Create secret project {}?",
                progress::terminal_text(&name)
            ))?,
            "canceled; secret project was not created"
        );
        dispatch_secrets(
            globals,
            SecretOperation::Projects(SecretProjectCommand::Create(SecretProjectCreateArgs {
                name: Some(name.clone()),
            })),
            placement,
        )
        .await?;
        name
    };
    Ok(format!(
        "{}:{selector}",
        if placement == StoragePlacement::Local {
            "local"
        } else {
            "platform"
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_stdin_after_maximum_crlf_is_not_silently_truncated() {
        let mut input = vec![b'x'; MAX_WORKLOAD_SECRET_VALUE_BYTES];
        input.extend_from_slice(b"\r\n");
        assert_eq!(
            read_workload_secret_bytes(input.as_slice(), false)
                .unwrap()
                .len(),
            MAX_WORKLOAD_SECRET_VALUE_BYTES
        );
        input.extend_from_slice(b"suffix");
        assert!(read_workload_secret_bytes(input.as_slice(), false).is_err());
    }

    #[test]
    fn canonical_secret_key_grammar_requires_an_explicit_scope() {
        for placement in ["--local", "--cloud"] {
            for scope in ["--project=development", "--user", "--organization"] {
                for tail in [
                    vec!["set", "DATABASE_URL"],
                    vec!["list", "--output", "json"],
                    vec!["delete", "DATABASE_URL"],
                    vec!["rename", "DATABASE_URL", "DATABASE_URL_NEXT"],
                ] {
                    let mut argv = vec!["cw", "secrets", placement, scope];
                    argv.extend(tail);
                    let args = secret_args(&argv);
                    let operation = resolve_secret_operation(args).unwrap();
                    match (scope, operation) {
                        ("--project=development", SecretOperation::Project { name, .. }) => {
                            assert_eq!(name, "development")
                        }
                        ("--user", SecretOperation::User(_))
                        | ("--organization", SecretOperation::Organization(_)) => {}
                        other => panic!("wrong secret scope: {other:?}"),
                    }
                }
            }
        }
        for tail in [
            vec!["set", "DATABASE_URL"],
            vec!["delete", "DATABASE_URL"],
            vec!["list"],
            vec!["rename", "A", "B"],
        ] {
            let mut argv = vec!["cw", "secrets", "--local"];
            argv.extend(tail);
            assert!(
                resolve_secret_operation(secret_args(&argv))
                    .unwrap_err()
                    .to_string()
                    .contains("--project=NAME")
            );
        }
    }

    fn secret_args(argv: &[&str]) -> SecretsArgs {
        let Command::Secrets(args) = Cli::try_parse_from(argv).unwrap().command else {
            panic!("expected secrets command")
        };
        args
    }

    #[test]
    fn retired_secret_grammar_and_conflicting_selections_are_rejected() {
        for argv in [
            vec![
                "cw",
                "secrets",
                "--local",
                "project",
                "set",
                "development",
                "KEY",
            ],
            vec!["cw", "secrets", "--local", "user", "list"],
            vec!["cw", "secrets", "--cloud", "organization", "list"],
            vec!["cw", "secrets", "--all-placements", "list"],
            vec!["cw", "secrets", "--local", "--cloud", "--user", "list"],
            vec![
                "cw",
                "secrets",
                "--local",
                "--project=development",
                "--user",
                "list",
            ],
            vec![
                "cw",
                "secrets",
                "--cloud",
                "--user",
                "--organization",
                "list",
            ],
            vec![
                "cw",
                "secrets",
                "--local",
                "--project=development",
                "set",
                "KEY",
                "raw-value-must-not-be-an-argument",
            ],
            vec![
                "cw",
                "secrets",
                "--local",
                "projects",
                "list",
                "development",
            ],
            vec![
                "cw",
                "secrets",
                "--local",
                "projects",
                "set",
                "development",
                "KEY",
            ],
        ] {
            // A conflicting placement is refused as the parsed flags are read.
            assert!(
                Cli::try_parse_from(&argv)
                    .map_err(drop)
                    .and_then(|cli| cli.placement().map_err(drop))
                    .is_err(),
                "accepted retired/conflicting grammar: {argv:?}"
            );
        }
    }

    #[test]
    fn key_deletion_never_becomes_project_deletion_for_missing_or_blank_keys() {
        for placement in ["--local", "--cloud"] {
            for scope in ["--project=development", "--user", "--organization"] {
                assert!(
                    Cli::try_parse_from(["cw", "secrets", placement, scope, "delete"]).is_err()
                );
                for key in ["", " ", "\t", "INVALID KEY", "1INVALID"] {
                    assert!(
                        Cli::try_parse_from(["cw", "secrets", placement, scope, "delete", key])
                            .is_err()
                    );
                }
            }
            let operation = resolve_secret_operation(secret_args(&[
                "cw",
                "secrets",
                placement,
                "--project=development",
                "delete",
                "DATABASE_URL",
            ]))
            .unwrap();
            assert!(
                matches!(operation, SecretOperation::Project { name, command: ScopedSecretCommand::Delete(args) }
                if name == "development" && args.key == "DATABASE_URL")
            );
        }
    }

    #[test]
    fn project_lifecycle_requires_its_own_nonblank_name_and_no_scope_flags() {
        for placement in ["--local", "--cloud"] {
            for command in ["create", "delete"] {
                let missing =
                    Cli::try_parse_from(["cw", "secrets", placement, "projects", command]);
                if command == "create" {
                    assert!(matches!(
                        missing.unwrap().command,
                        Command::Secrets(SecretsArgs {
                            command: SecretsCommand::Projects {
                                command: SecretProjectCommand::Create(SecretProjectCreateArgs {
                                    name: None
                                })
                            },
                            ..
                        })
                    ));
                } else {
                    assert!(missing.is_err());
                }
                for name in ["", " "] {
                    assert!(
                        Cli::try_parse_from([
                            "cw", "secrets", placement, "projects", command, name
                        ])
                        .is_err()
                    );
                }
                assert!(matches!(
                    resolve_secret_operation(secret_args(&[
                        "cw",
                        "secrets",
                        placement,
                        "projects",
                        command,
                        "development"
                    ]))
                    .unwrap(),
                    SecretOperation::Projects(_)
                ));
                assert!(
                    resolve_secret_operation(secret_args(&[
                        "cw",
                        "secrets",
                        placement,
                        "--project=other",
                        "projects",
                        command,
                        "development"
                    ]))
                    .is_err()
                );
            }
            assert!(
                Cli::try_parse_from(["cw", "secrets", placement, "--project=", "list"]).is_err()
            );
        }
    }

    #[test]
    fn project_deletion_is_default_no_and_eof_never_confirms() {
        for (input, expected) in [
            ("", false),
            ("\n", false),
            ("no\n", false),
            ("y\n", true),
            ("yes\n", true),
        ] {
            let mut output = Vec::new();
            assert_eq!(
                read_secret_project_delete_confirmation(
                    "local secret project \"development\" (project-id)",
                    input.as_bytes(),
                    &mut output
                )
                .unwrap(),
                expected
            );
            assert_eq!(
                String::from_utf8(output).unwrap(),
                "Delete local secret project \"development\" (project-id) and all its keys? [y/N]: "
            );
        }
        let oversized = format!("yes{}unread", " ".repeat(128));
        assert!(
            !read_secret_project_delete_confirmation(
                "development",
                oversized.as_bytes(),
                Vec::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn scoped_secret_metadata_never_contains_values() {
        let metadata = SecretMetadata {
            key: "DATABASE_URL".to_owned(),
            created_at: "2026-09-03T00:00:00Z".to_owned(),
            updated_at: "2026-09-03T00:00:01Z".to_owned(),
        };
        let json = serde_json::to_value(metadata).unwrap();
        assert_eq!(json["key"], "DATABASE_URL");
        assert_eq!(json.as_object().unwrap().len(), 3);
        assert!(json.get("value").is_none());
    }

    #[test]
    fn metadata_preview_stays_explicit_read_only_and_json_never_prompts() {
        for placement in ["--local", "--cloud"] {
            let Command::Secrets(args) = Cli::try_parse_from([
                "cw",
                "secrets",
                placement,
                "preview",
                "--file",
                "project.yaml",
                "--output",
                "json",
            ])
            .unwrap()
            .command
            else {
                panic!("expected secrets command")
            };
            let SecretsCommand::Preview(preview) = args.command else {
                panic!("expected secret preview")
            };
            assert_eq!(preview.file, PathBuf::from("project.yaml"));
            assert_eq!(preview.output, OutputFormat::Json);
        }
        assert!(
            resolve_secret_operation(secret_args(&[
                "cw",
                "secrets",
                "--local",
                "--project=development",
                "preview"
            ]))
            .is_err()
        );
        for tail in [
            vec!["--project=development", "list"],
            vec!["--user", "list"],
            vec!["--organization", "list"],
            vec!["projects", "list"],
            vec!["preview"],
        ] {
            let mut argv = vec!["cw", "secrets"];
            argv.extend(tail);
            argv.extend(["--output", "json"]);
            let operation = resolve_secret_operation(secret_args(&argv)).unwrap();
            assert!(secret_operation_json(&operation));
            assert!(
                resolve_storage_placement(false, false, secret_operation_json(&operation)).is_err()
            );
        }
    }

    #[test]
    fn secret_preview_loads_only_selectors_and_explicit_environment_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("codewire.yaml");
        fs::write(
            &path,
            r#"
secrets:
  organization: true
  project: development
  user: platform
environment:
  Z_TOKEN: synthetic-z
  A_TOKEN: synthetic-a
"#,
        )
        .unwrap();

        let intent = load_secret_preview_intent(&path).unwrap();
        assert!(intent.organization);
        assert_eq!(intent.user, Some(StoragePlacement::Platform));
        assert_eq!(intent.project.as_deref(), Some("development"));
        assert_eq!(
            intent
                .explicit_environment_keys
                .into_iter()
                .collect::<Vec<_>>(),
            ["A_TOKEN", "Z_TOKEN"]
        );
    }

    #[test]
    fn secret_preview_rejects_unsupported_and_mismatched_source_origins() {
        for placement in [StoragePlacement::Local, StoragePlacement::Platform] {
            let mut intent = SecretPreviewIntent {
                organization: false,
                project: Some("development".to_owned()),
                user: None,
                explicit_environment_keys: BTreeSet::new(),
            };
            validate_secret_preview_placement(&intent, placement).unwrap();
            for origin in ["local", "platform", "unknown"] {
                intent.project = Some(format!("{origin}:development"));
                let expected = matches!(
                    (origin, placement),
                    ("local", StoragePlacement::Local) | ("platform", StoragePlacement::Platform)
                );
                assert_eq!(
                    validate_secret_preview_placement(&intent, placement).is_ok(),
                    expected
                );
            }
            intent.project = None;
            intent.user = Some(placement);
            validate_secret_preview_placement(&intent, placement).unwrap();
            intent.user = Some(if placement == StoragePlacement::Local {
                StoragePlacement::Platform
            } else {
                StoragePlacement::Local
            });
            assert!(validate_secret_preview_placement(&intent, placement).is_err());
            intent.user = None;
            intent.organization = true;
            assert_eq!(
                validate_secret_preview_placement(&intent, placement).is_ok(),
                placement == StoragePlacement::Platform
            );
        }
    }

    #[test]
    fn secret_preview_presentation_is_metadata_only() {
        let rows = vec![SecretResolutionView {
            placement: "platform",
            key: "DATABASE_URL".into(),
            source: "explicit_environment",
            overridden_sources: vec!["organization", "project", "user"],
        }];
        let json = serde_json::to_value(rows).unwrap();
        assert_eq!(json[0]["placement"], "platform");
        assert_eq!(json[0]["source"], "explicit_environment");
        assert!(json[0].get("value").is_none());
    }

    #[test]
    fn secret_stdin_is_bounded_and_strips_only_one_line_ending() {
        assert_eq!(
            read_workload_secret_bytes(&b"synthetic\r\n"[..], false)
                .unwrap()
                .as_slice(),
            b"synthetic"
        );
        assert_eq!(
            read_workload_secret_bytes(&b" leading \nline 2 \n\n"[..], false)
                .unwrap()
                .as_slice(),
            b" leading \nline 2 \n"
        );
        assert!(read_workload_secret_bytes(&b""[..], false).is_err());
        assert!(read_workload_secret_bytes(&b"a\0b"[..], false).is_err());
        assert!(
            read_workload_secret_bytes(
                vec![b'a'; MAX_WORKLOAD_SECRET_VALUE_BYTES + 1].as_slice(),
                false,
            )
            .is_err()
        );
        let mut maximum = vec![b'a'; MAX_WORKLOAD_SECRET_VALUE_BYTES];
        maximum.push(b'\n');
        assert_eq!(
            read_workload_secret_bytes(maximum.as_slice(), false)
                .unwrap()
                .len(),
            MAX_WORKLOAD_SECRET_VALUE_BYTES
        );
    }
}
