//! The `cw secrets` command line: its subcommands, scopes and arguments.

use super::*;

#[derive(Debug, Subcommand)]
pub(crate) enum SecretsCommand {
    #[command(
        visible_alias = "ls",
        about = "List key metadata in the explicitly selected scope"
    )]
    List(SecretKeyListArgs),
    #[command(about = "Set one key; guide missing scope/name and read a hidden value or stdin")]
    Set(ScopedSecretKeyArgs),
    #[command(about = "Delete one key from the explicitly selected scope")]
    Delete(ScopedSecretDeleteArgs),
    #[command(about = "Rename one key in the explicitly selected scope")]
    Rename(ScopedSecretRenameArgs),
    #[command(about = "Preview key/source resolution from codewire.yaml")]
    Preview(SecretPreviewArgs),
    #[command(about = "Manage named secret projects")]
    Projects {
        #[command(subcommand)]
        command: SecretProjectCommand,
    },
    #[command(
        hide = true,
        about = "List the presets --preset fills a key's hosts and header from"
    )]
    Presets(ScopedSecretListArgs),
}

/// `--local` or `--cloud` (global) selects the protected storage; without
/// one an interactive call prompts.
#[derive(Debug, Args)]
pub(crate) struct SecretsArgs {
    #[arg(long, value_name = "NAME", conflicts_with_all = ["user", "organization"], value_parser = parse_secret_project_reference, help = "Explicit named project for key operations; never inferred from cw use or YAML")]
    pub(crate) project: Option<String>,
    #[arg(long, conflicts_with_all = ["project", "organization"], help = "Operate on user-scoped keys")]
    pub(crate) user: bool,
    #[arg(long, conflicts_with_all = ["project", "user"], help = "Operate on organization-scoped keys (platform only)")]
    pub(crate) organization: bool,
    #[command(subcommand)]
    pub(crate) command: SecretsCommand,
}

#[derive(Debug, Args)]
pub(crate) struct SecretPreviewArgs {
    #[arg(
        long,
        default_value = "codewire.yaml",
        help = "Project document to preview"
    )]
    pub(crate) file: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SecretProjectCommand {
    #[command(about = "Create a secret project; asks for a missing name at a terminal")]
    Create(SecretProjectCreateArgs),
    #[command(visible_alias = "ls", about = "List named secret projects")]
    List(ScopedSecretListArgs),
    #[command(about = "Delete an explicitly named project and all its keys")]
    Delete(SecretProjectDeleteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SecretProjectCreateArgs {
    #[arg(value_name = "NAME", value_parser = parse_secret_project_name)]
    pub(crate) name: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SecretProjectDeleteArgs {
    #[arg(value_name = "NAME", value_parser = parse_secret_project_reference)]
    pub(crate) name: String,
    #[arg(long, help = "Confirm deletion of this project and all its keys")]
    pub(crate) yes: bool,
}

#[derive(Debug)]
pub(crate) enum ScopedSecretCommand {
    List(SecretKeyListArgs),
    Set(ScopedSecretKeyArgs),
    Delete(ScopedSecretDeleteArgs),
    Rename(ScopedSecretRenameArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

/// A key list: `-v` adds each key's header, scheme, prefix, every host and
/// when it was created.
#[derive(Debug, Args)]
pub(crate) struct SecretKeyListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
    #[arg(
        short,
        long,
        help = "Also show each key's header, scheme, prefix, every host and when it was created"
    )]
    pub(crate) verbose: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretKeyArgs {
    #[arg(value_name = "KEY", value_parser = parse_secret_key)]
    pub(crate) key: Option<String>,
    #[command(flatten)]
    pub(crate) binding: SecretBindingArgs,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
    #[arg(skip)]
    pub(crate) guided: bool,
    #[arg(skip)]
    pub(crate) new_project: bool,
    /// [`codewire_access::HOST_BOUND_SECRETS`], as the command was given it.
    #[arg(skip)]
    pub(crate) host_bound: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretDeleteArgs {
    #[arg(value_name = "KEY", value_parser = parse_secret_key)]
    pub(crate) key: String,
}

#[derive(Debug, Args)]
pub(crate) struct ScopedSecretRenameArgs {
    #[arg(value_name = "OLD_KEY", value_parser = parse_secret_key)]
    pub(crate) old_key: String,
    #[arg(value_name = "NEW_KEY", value_parser = parse_secret_key)]
    pub(crate) new_key: String,
}
