use serde::Serialize;
use std::path::Path;

use super::*;

#[cfg(target_os = "linux")]
use codewire_local_credentials::{
    LocalCredentialClient, LocalSecretProject, WorkloadSecretMetadata, WorkloadSecretSelection,
};
#[cfg(target_os = "linux")]
use codewire_protected_store::ProtectedValue;
use codewire_workload_secrets::{
    MAX_WORKLOAD_SECRET_VALUE_BYTES, ResolvedWorkloadSecretMetadata, WorkloadSecretSource,
    validate_workload_secret_value,
};
use std::io::{BufRead as _, Read as _};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretPlacement {
    Local,
    Platform,
    All,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct SecretInventoryView {
    pub(crate) placement: &'static str,
    pub(crate) scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) project: Option<String>,
    pub(crate) key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) updated_at: String,
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
    pub(crate) user: bool,
    pub(crate) explicit_environment_keys: BTreeSet<String>,
}

pub(crate) async fn handle_secrets_command(
    globals: &Globals,
    args: SecretsArgs,
) -> anyhow::Result<()> {
    let placement = secret_placement(&args)?;
    validate_secret_command_placement(placement, &args.command)?;
    match placement {
        SecretPlacement::Platform => handle_platform_secrets_command(globals, args.command).await,
        SecretPlacement::Local => handle_local_secrets_command(args.command).await,
        SecretPlacement::All => {
            let SecretsCommand::List(list) = args.command else {
                unreachable!("all-placement mutation rejected above")
            };
            let mut inventory = local_secret_inventory().await?;
            inventory.extend(platform_secret_inventory(globals).await?);
            inventory.sort_by(|left, right| {
                (
                    left.placement,
                    left.scope,
                    left.project.as_deref(),
                    left.key.as_str(),
                )
                    .cmp(&(
                        right.placement,
                        right.scope,
                        right.project.as_deref(),
                        right.key.as_str(),
                    ))
            });
            print_secret_inventory(&inventory, list.output)
        }
    }
}

fn validate_secret_command_placement(
    placement: SecretPlacement,
    command: &SecretsCommand,
) -> anyhow::Result<()> {
    if placement == SecretPlacement::All && !matches!(command, SecretsCommand::List(_)) {
        anyhow::bail!("--all-placements is available only for 'cw secrets list'");
    }
    Ok(())
}

fn secret_placement(args: &SecretsArgs) -> anyhow::Result<SecretPlacement> {
    match (args.local, args.platform, args.all_placements) {
        (true, false, false) => Ok(SecretPlacement::Local),
        (false, true, false) => Ok(SecretPlacement::Platform),
        (false, false, true) => Ok(SecretPlacement::All),
        (false, false, false) => anyhow::bail!(
            "secret placement is required: pass --local, --platform, or --all-placements"
        ),
        _ => anyhow::bail!(
            "secret placement must be exactly one of --local, --platform, or --all-placements"
        ),
    }
}

pub(crate) fn print_secret_inventory(
    inventory: &[SecretInventoryView],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(inventory)?),
        OutputFormat::Text if inventory.is_empty() => println!("No workload secrets found."),
        OutputFormat::Text => {
            println!(
                "{:<10} {:<14} {:<24} {:<32} UPDATED",
                "PLACEMENT", "SCOPE", "PROJECT", "KEY"
            );
            for secret in inventory {
                println!(
                    "{:<10} {:<14} {:<24} {:<32} {}",
                    secret.placement,
                    secret.scope,
                    secret.project.as_deref().unwrap_or("-"),
                    secret.key,
                    secret.updated_at,
                );
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn handle_local_secrets_command(_command: SecretsCommand) -> anyhow::Result<()> {
    anyhow::bail!("local workload-secret management is not available on this operating system")
}

#[cfg(not(target_os = "linux"))]
async fn local_secret_inventory() -> anyhow::Result<Vec<SecretInventoryView>> {
    anyhow::bail!("local workload-secret management is not available on this operating system")
}

#[cfg(target_os = "linux")]
async fn handle_local_secrets_command(command: SecretsCommand) -> anyhow::Result<()> {
    let mut client = connect_local_credential_authority().await?;
    match command {
        SecretsCommand::List(args) => {
            let inventory = local_secret_inventory_with_client(&mut client).await?;
            print_secret_inventory(&inventory, args.output)
        }
        SecretsCommand::Preview(args) => {
            let intent = load_secret_preview_intent(&args.file)?;
            let secrets = client
                .resolve_workload_secret_metadata(WorkloadSecretSelection {
                    organization: intent.organization,
                    project: intent.project,
                    user: intent.user,
                    explicit_environment_keys: intent.explicit_environment_keys,
                })
                .await
                .context("preview local workload-secret resolution")?;
            print_secret_resolution("local", &secrets, args.output)
        }
        SecretsCommand::Organization { .. } => {
            anyhow::bail!("organization workload secrets are unsupported locally")
        }
        SecretsCommand::User { command } => local_user_command(&mut client, command).await,
        SecretsCommand::Project { command } => local_project_command(&mut client, command).await,
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

#[cfg(target_os = "linux")]
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
            let key = trimmed_required(&args.key, "secret key")?.to_owned();
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

#[cfg(target_os = "linux")]
async fn local_project_command(
    client: &mut LocalCredentialClient,
    command: SecretProjectCommand,
) -> anyhow::Result<()> {
    match command {
        SecretProjectCommand::Create(args) => {
            let name = trimmed_required(&args.name, "secret project name")?.to_owned();
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
            if let Some(name) = args.project_name.as_deref() {
                let project = resolve_local_project(&projects, name)?;
                let secrets = client
                    .list_project_workload_secrets(project.id)
                    .await
                    .context("list local project secrets")?;
                print_local_secret_metadata(
                    &secrets,
                    &format!("No local secrets in project {:?}.", project.name),
                    args.output,
                )
            } else {
                print_local_secret_projects(&projects, args.output)
            }
        }
        SecretProjectCommand::Set(args) => {
            let project = resolve_local_project_by_name(client, &args.project).await?;
            let key = trimmed_required(&args.key, "secret key")?.to_owned();
            let value = prompt_workload_secret_value()?;
            client
                .set_project_workload_secret(project.id, key.clone(), value)
                .await
                .context("set local project secret")?;
            eprintln!("Local secret {key} set in project {:?}.", project.name);
            Ok(())
        }
        SecretProjectCommand::Delete(args) => {
            let project = resolve_local_project_by_name(client, &args.project).await?;
            if let Some(key) = args.key.as_deref() {
                let key = trimmed_required(key, "secret key")?.to_owned();
                client
                    .delete_project_workload_secret(project.id, key.clone())
                    .await
                    .context("delete local project secret")?;
                eprintln!(
                    "Local secret {key} deleted from project {:?}.",
                    project.name
                );
            } else {
                if !args.yes
                    && !prompt_confirm_default_yes(&format!(
                        "Delete local secret project {:?} and all its secrets? [Y/n]",
                        project.name
                    ))?
                {
                    eprintln!("Canceled.");
                    return Ok(());
                }
                client
                    .delete_secret_project(project.id)
                    .await
                    .context("delete local secret project")?;
                eprintln!("Local secret project {:?} deleted.", project.name);
            }
            Ok(())
        }
        SecretProjectCommand::Rename(args) => {
            let project = resolve_local_project_by_name(client, &args.project).await?;
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn resolve_local_project<'a>(
    projects: &'a [LocalSecretProject],
    name: &str,
) -> anyhow::Result<&'a LocalSecretProject> {
    let name = trimmed_required(name, "secret project name")?;
    projects
        .iter()
        .find(|project| project.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| anyhow::anyhow!("local secret project {name:?} not found"))
}

#[cfg(target_os = "linux")]
async fn local_secret_inventory() -> anyhow::Result<Vec<SecretInventoryView>> {
    let mut client = connect_local_credential_authority().await?;
    local_secret_inventory_with_client(&mut client).await
}

#[cfg(target_os = "linux")]
async fn local_secret_inventory_with_client(
    client: &mut LocalCredentialClient,
) -> anyhow::Result<Vec<SecretInventoryView>> {
    let mut inventory = client
        .list_user_workload_secrets()
        .await
        .context("list local user secrets")?
        .into_iter()
        .map(|secret| local_inventory_entry("user", None, secret))
        .collect::<Vec<_>>();
    for project in client
        .list_secret_projects()
        .await
        .context("list local secret projects")?
    {
        inventory.extend(
            client
                .list_project_workload_secrets(project.id)
                .await
                .context("list local project secrets")?
                .into_iter()
                .map(|secret| local_inventory_entry("project", Some(project.name.clone()), secret)),
        );
    }
    Ok(inventory)
}

#[cfg(target_os = "linux")]
fn local_inventory_entry(
    scope: &'static str,
    project: Option<String>,
    secret: WorkloadSecretMetadata,
) -> SecretInventoryView {
    SecretInventoryView {
        placement: "local",
        scope,
        project,
        key: secret.key,
        created_at: format_unix_millis(secret.created_at_unix_ms),
        updated_at: format_unix_millis(secret.updated_at_unix_ms),
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn format_unix_millis(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
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
        eprint!("Value: ");
        std::io::stderr().flush().context("flush secret prompt")?;
    }
    let echo_guard = if interactive {
        Some(EchoGuard::disable_if_tty()?)
    } else {
        None
    };
    let stdin = std::io::stdin();
    let value = read_workload_secret_bytes(stdin.lock(), interactive);
    drop(echo_guard);
    value
}

fn read_workload_secret_bytes<R: std::io::BufRead>(
    reader: R,
    single_line: bool,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let limit =
        u64::try_from(MAX_WORKLOAD_SECRET_VALUE_BYTES + 2).expect("workload-secret value limit");
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

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn canonical_secret_grammar_is_placement_explicit_and_legacy_forms_are_gone() {
        let Command::Secrets(args) = Cli::try_parse_from([
            "cw",
            "secrets",
            "--local",
            "project",
            "set",
            "development",
            "API_TOKEN",
        ])
        .unwrap()
        .command
        else {
            panic!("expected secrets command")
        };
        assert!(args.local);
        assert!(matches!(
            args.command,
            SecretsCommand::Project {
                command: SecretProjectCommand::Set(_)
            }
        ));
        assert!(Cli::try_parse_from(["cw", "secrets", "set", "development", "TOKEN"]).is_err());
        assert!(Cli::try_parse_from(["cw", "secrets", "--local", "org", "list"]).is_err());
        assert!(
            Cli::try_parse_from(["cw", "secrets", "--local", "--platform", "user", "list"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["cw", "secrets", "--all-placements", "list"]).is_ok());
        for placement in ["--local", "--platform"] {
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
        let Command::Secrets(args) =
            Cli::try_parse_from(["cw", "secrets", "--all-placements", "preview"])
                .unwrap()
                .command
        else {
            panic!("expected secrets command")
        };
        let placement = secret_placement(&args).unwrap();
        assert_eq!(placement, SecretPlacement::All);
        assert!(validate_secret_command_placement(placement, &args.command).is_err());
    }

    #[test]
    fn secret_inventory_text_names_placement_and_never_has_a_value_field() {
        let inventory = vec![SecretInventoryView {
            placement: "local",
            scope: "user",
            project: None,
            key: "DATABASE_URL".into(),
            created_at: "2026-09-03T00:00:00Z".into(),
            updated_at: "2026-09-03T00:00:01Z".into(),
        }];
        let json = serde_json::to_string(&inventory).unwrap();
        assert!(json.contains("\"placement\":\"local\""));
        assert!(!json.contains("value"));
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
  user: true
environment:
  Z_TOKEN: synthetic-z
  A_TOKEN: synthetic-a
"#,
        )
        .unwrap();

        let intent = load_secret_preview_intent(&path).unwrap();
        assert!(intent.organization);
        assert!(intent.user);
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
