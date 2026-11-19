//! The arguments of `cw credentials profiles` and of the profile selected
//! with `--profile`, moved out of `mod.rs` unchanged.

use super::*;

#[derive(Debug)]
pub(crate) enum CredentialProfileCommand {
    List(CredentialListArgs),
    Get(CredentialProfileSelectorArgs),
    Set(CredentialProfileSetArgs),
    Unset(CredentialProfileSlotArgs),
    Revisions(CredentialProfileSelectorArgs),
    Delete(CredentialProfileDeleteArgs),
    Default(CredentialProfileDefaultArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum CredentialProfilesCommand {
    #[command(visible_alias = "ls", about = "List profiles")]
    List(CredentialListArgs),
    #[command(
        about = "Make a cloud profile your default",
        long_about = "Make a cloud profile your default. A cloud `cw create` uses it when you name no profile, the dashboard preselects it, and lists show it first. Your first profile becomes your default, and the default cannot be deleted: make another profile the default first."
    )]
    Default(CredentialProfileDefaultArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CredentialProfileDefaultArgs {
    #[arg(value_name = "PROFILE", help = "Profile name or id:<canonical-uuid>")]
    pub(crate) profile: String,
}

#[derive(Debug)]
pub(crate) struct CredentialProfileSelectorArgs {
    pub(crate) profile: String,
    pub(crate) revision: Option<u64>,
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialProfileSetArgs {
    #[arg(skip)]
    pub(crate) profile: String,
    #[arg(value_name = "PROVIDER", value_parser = PROFILE_SLOTS, help = SLOT_HELP)]
    pub(crate) slot: Option<String>,
    #[arg(value_name = "CREDENTIAL", help = SELECTOR_HELP)]
    pub(crate) credential: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CredentialProfileSlotArgs {
    #[arg(skip)]
    pub(crate) profile: String,
    #[arg(value_name = "PROVIDER", value_parser = PROFILE_SLOTS, help = SLOT_HELP)]
    pub(crate) slot: String,
}

#[derive(Debug)]
pub(crate) struct CredentialProfileDeleteArgs {
    pub(crate) profile: String,
    pub(crate) yes: bool,
}
