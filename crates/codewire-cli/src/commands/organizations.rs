//! `cw org`: organizations, their members and invitations.

use super::*;

#[derive(Debug, Subcommand)]
pub(crate) enum OrgCommand {
    #[command(visible_alias = "ls", about = "List organizations")]
    List(OrgListArgs),
    #[command(about = "Show the current organization")]
    Current,
    #[command(about = "Set the current organization")]
    Set(OrgSetArgs),
    #[command(about = "Create a new organization")]
    Create(OrgCreateArgs),
    #[command(about = "Delete an organization")]
    Delete(OrgDeleteArgs),
    #[command(about = "Invite a member to an organization")]
    Invite(OrgInviteArgs),
    #[command(about = "List your pending invitations")]
    Invitations(OrgInvitationsArgs),
    #[command(about = "Accept an invitation to an organization")]
    Accept(OrgAcceptArgs),
    #[command(about = "List an organization's members")]
    Members(OrgMembersArgs),
    #[command(about = "Manage an organization's members")]
    Member {
        #[command(subcommand)]
        command: OrgMemberCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum OrgMemberCommand {
    #[command(
        visible_alias = "remove",
        about = "Remove a member from an organization"
    )]
    Rm(OrgMemberRmArgs),
}

#[derive(Debug, Args)]
pub(crate) struct OrgInvitationsArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(super) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct OrgAcceptArgs {
    #[arg(
        value_name = "ORG",
        help = "The organization's slug, name or ID, as `cw org invitations` lists it"
    )]
    pub(super) org: String,
}

#[derive(Debug, Args)]
pub(crate) struct OrgMembersArgs {
    #[arg(
        long,
        value_name = "ID_OR_SLUG",
        help = "Organization ID or slug (default: the current organization)"
    )]
    pub(super) org: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(super) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct OrgMemberRmArgs {
    #[arg(value_name = "USER", help = "The member's user ID or email address")]
    pub(super) user: String,
    #[arg(
        long,
        value_name = "ID_OR_SLUG",
        help = "Organization ID or slug (default: the current organization)"
    )]
    pub(super) org: Option<String>,
    #[arg(long, help = "Skip confirmation prompt")]
    pub(super) yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OrgListArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(super) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct OrgSetArgs {
    #[arg(value_name = "ID_OR_SLUG")]
    pub(super) id_or_slug: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct OrgCreateArgs {
    #[arg(
        value_name = "NAME",
        help = "Organization name; omit for an interactive walkthrough"
    )]
    pub(super) name: Option<String>,
    #[arg(long, help = "URL-safe slug (default: auto-generated from name)")]
    pub(super) slug: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct OrgDeleteArgs {
    #[arg(value_name = "ID_OR_SLUG")]
    pub(super) id_or_slug: String,
    #[arg(long, help = "Skip confirmation prompt")]
    pub(super) yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OrgInviteArgs {
    #[arg(
        value_name = "EMAIL",
        help = "Invitation recipient; omit for an interactive walkthrough"
    )]
    pub(super) email: Option<String>,
    #[arg(long, help = "Role to assign (owner, admin, member; default: member)")]
    pub(super) role: Option<String>,
    #[arg(long, value_name = "ID_OR_SLUG", help = "Organization ID or slug")]
    pub(super) org: Option<String>,
}

pub(crate) async fn handle_org_command(
    globals: &Globals,
    mut command: Option<OrgCommand>,
) -> anyhow::Result<()> {
    let guided = super::additions::org_metadata(&mut command)?;
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let client = organization_client(&platform)?;

    match command.unwrap_or(OrgCommand::Set(OrgSetArgs { id_or_slug: None })) {
        OrgCommand::List(args) => {
            let orgs = client.list_orgs().await.context("list orgs")?;
            print_orgs(&orgs, platform.default_org.as_deref(), args.output)?;
        }
        OrgCommand::Current => {
            let orgs = client.list_orgs().await.context("list orgs")?;
            let org_id = current_org_id(&platform, &orgs)?;
            let org = orgs
                .iter()
                .find(|org| org.id == org_id)
                .ok_or_else(|| anyhow::anyhow!("current organization {org_id:?} not found"))?;
            print_org_current(org);
        }
        OrgCommand::Set(args) => set_org(&client, &platform, &paths, args).await?,
        OrgCommand::Create(args) => create_org(&client, args, guided).await?,
        OrgCommand::Delete(args) => delete_org(&client, &platform, args).await?,
        OrgCommand::Invite(args) => invite(&client, &platform, args, guided).await?,
        OrgCommand::Invitations(args) => {
            let invitations = client
                .list_my_invitations()
                .await
                .context("list invitations")?;
            print_pending_invitations(&invitations, args.output)?;
        }
        OrgCommand::Accept(args) => eprintln!("{}", accept(&client, &args.org).await?),
        OrgCommand::Members(args) => {
            let orgs = client.list_orgs().await.context("list orgs")?;
            let org_id = resolve_org_id(&platform, &orgs, args.org.as_deref())?;
            let members = client.list_members(&org_id).await.context("list members")?;
            print_members(&members, args.output)?;
        }
        OrgCommand::Member {
            command: OrgMemberCommand::Rm(args),
        } => remove(&client, &platform, args).await?,
    }

    Ok(())
}

async fn set_org(
    client: &OrganizationClient,
    platform: &config::ResolvedPlatformConfig,
    paths: &ResolvePaths,
    args: OrgSetArgs,
) -> anyhow::Result<()> {
    let orgs = client.list_orgs().await.context("list orgs")?;
    let selected = super::additions::org_choice(&orgs, args.id_or_slug.as_deref())?;
    let mut saved = config::load_platform_config(&paths.platform_config_dir)?;
    if !config::same_server_url(&saved.server_url, &platform.server_url) {
        anyhow::bail!(
            "cannot save current org for {}; saved config is for {}",
            platform.server_url,
            config::normalize_server_url(&saved.server_url)
        );
    }
    saved.default_org = selected.id.clone();
    config::save_platform_config(&paths.platform_config_dir, &saved).context("save config")?;
    eprintln!("Current org set to {} ({}).", selected.name, selected.slug);
    Ok(())
}

async fn create_org(
    client: &OrganizationClient,
    args: OrgCreateArgs,
    guided: bool,
) -> anyhow::Result<()> {
    let name = trimmed_required(
        args.name
            .as_deref()
            .context("organization name is required")?,
        "organization name",
    )?;
    let slug = args
        .slug
        .as_deref()
        .and_then(trimmed_str)
        .map(str::to_string)
        .unwrap_or_else(|| slugify(name));
    if guided {
        super::additions::review(
            "Create organization?",
            &[("Name", name.to_owned()), ("Slug", slug.clone())],
        )?;
    }
    let org = client
        .create_org(&CreateOrgRequest {
            name: name.to_string(),
            slug,
        })
        .await
        .context("create org")?;
    eprintln!("Created organization {:?} (slug: {}).", org.name, org.slug);
    Ok(())
}

async fn delete_org(
    client: &OrganizationClient,
    platform: &config::ResolvedPlatformConfig,
    args: OrgDeleteArgs,
) -> anyhow::Result<()> {
    let id_or_slug = trimmed_required(&args.id_or_slug, "organization id or slug")?;
    let orgs = client.list_orgs().await.context("list orgs")?;
    let org_id = resolve_org_id(platform, &orgs, Some(id_or_slug))?;
    let org_name = orgs
        .iter()
        .find(|org| org.id == org_id)
        .map(|org| org.name.as_str())
        .unwrap_or(id_or_slug);
    if !args.yes {
        confirm_delete("organization", org_name)?;
    }
    match client.delete_org(&org_id).await.context("delete org")? {
        OrganizationDeletionStart::Accepted(operation) => {
            eprintln!(
                "{}",
                organization_deletion_started_message(&operation.operation_id)
            );
            match client
                .wait_for_org_deletion(&org_id, &operation.operation_id)
                .await
                .context("observe organization deletion")?
            {
                OrganizationDeletionOutcome::Completed => {
                    eprintln!("Organization deleted.");
                }
                OrganizationDeletionOutcome::Failed {
                    operation_id,
                    failure_code,
                } => {
                    anyhow::bail!(
                        "organization deletion {operation_id} failed ({failure_code}); the organization is retained for retry"
                    );
                }
                OrganizationDeletionOutcome::PollingStopped { operation_id } => {
                    eprintln!(
                        "{}",
                        organization_deletion_polling_stopped_message(&operation_id)
                    );
                }
            }
        }
    }
    Ok(())
}

async fn invite(
    client: &OrganizationClient,
    platform: &config::ResolvedPlatformConfig,
    args: OrgInviteArgs,
    guided: bool,
) -> anyhow::Result<()> {
    let email = trimmed_required(args.email.as_deref().context("email is required")?, "email")?;
    let role = trimmed_required(args.role.as_deref().unwrap_or("member"), "role")?;
    let orgs = client.list_orgs().await.context("list orgs")?;
    let org_id = if guided && args.org.is_none() {
        super::additions::org_choice(&orgs, None)?.id.clone()
    } else {
        resolve_org_id(platform, &orgs, args.org.as_deref())?
    };
    if guided {
        super::additions::review(
            "Send invitation?",
            &[
                ("Organization", org_id.clone()),
                ("Email", email.to_owned()),
                ("Role", role.to_owned()),
            ],
        )?;
    }
    let created = client
        .create_invitation(
            &org_id,
            &CreateInvitationRequest {
                email: email.to_string(),
                role: role.to_string(),
            },
        )
        .await
        .context("invite")?;
    eprintln!(
        "Created an invitation for {} as {}. Its one-time link:",
        created.invitation.email, created.invitation.role
    );
    println!("{}", created.url);
    eprintln!(
        "{}",
        report_invitation_email(client, &org_id, &created).await
    );
    Ok(())
}

/// `cw org member rm`: confirms, then removes the member.
async fn remove(
    client: &OrganizationClient,
    platform: &config::ResolvedPlatformConfig,
    args: OrgMemberRmArgs,
) -> anyhow::Result<()> {
    let orgs = client.list_orgs().await.context("list orgs")?;
    let org_id = resolve_org_id(platform, &orgs, args.org.as_deref())?;
    let org_name = orgs
        .iter()
        .find(|org| org.id == org_id)
        .map_or(org_id.as_str(), |org| org.name.as_str());
    let confirm = |member: &Member| {
        Ok(args.yes
            || prompt_confirm_default_no(&format!(
                "Remove {} ({}) from {org_name}?",
                member.email, member.role
            ))?)
    };
    if let Some(removed) = remove_member(client, &org_id, &args.user, confirm).await? {
        eprintln!("Removed {} from {org_name}.", removed.email);
    }
    Ok(())
}

/// Accepts the caller's pending invitation to `org` (a slug, name or ID) by
/// its id, and says what happened.
async fn accept(client: &OrganizationClient, org: &str) -> anyhow::Result<String> {
    let invitations = client
        .list_my_invitations()
        .await
        .context("list invitations")?;
    let invitation = select_invitation(&invitations, org)?;
    match client
        .accept_invitation(&invitation.id)
        .await
        .context("accept invitation")?
    {
        Acceptance::Joined { .. } => Ok(format!(
            "Joined {} ({}) as {}.",
            invitation.org_name, invitation.org_slug, invitation.role
        )),
        Acceptance::EmailUnverified => anyhow::bail!(
            "your email address is not verified; verify it first (follow the link in Codewire's verification email), then run `cw org accept {org}` again"
        ),
    }
}

/// The one pending invitation `org` names: by slug or ID exactly, or by
/// organization name ignoring case.
fn select_invitation<'a>(
    invitations: &'a [PendingInvitation],
    org: &str,
) -> anyhow::Result<&'a PendingInvitation> {
    let org = org.trim();
    let exact: Vec<_> = invitations
        .iter()
        .filter(|invitation| invitation.org_slug == org || invitation.org_id == org)
        .collect();
    let matches = if exact.is_empty() {
        invitations
            .iter()
            .filter(|invitation| invitation.org_name.eq_ignore_ascii_case(org))
            .collect()
    } else {
        exact
    };
    match matches.as_slice() {
        [invitation] => Ok(invitation),
        [] if invitations.is_empty() => anyhow::bail!(
            "no pending invitation to {org:?}: you have no pending invitations. Invitations are listed only for a verified email address; if you expected one, verify your address, then run `cw org accept {org}` again"
        ),
        [] => anyhow::bail!(
            "no pending invitation to {org:?}. Your pending invitations:\n{}",
            format_pending_invitations_text(invitations).trim_end()
        ),
        several => anyhow::bail!(
            "{org:?} names {} pending invitations; name one by slug: {}",
            several.len(),
            several
                .iter()
                .map(|invitation| invitation.org_slug.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn print_pending_invitations(
    invitations: &[PendingInvitation],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(invitations)?),
        OutputFormat::Text => print!("{}", format_pending_invitations_text(invitations)),
    }
    Ok(())
}

fn format_pending_invitations_text(invitations: &[PendingInvitation]) -> String {
    if invitations.is_empty() {
        return "No pending invitations. Invitations are listed only for a verified email address.\n"
            .to_owned();
    }
    let mut output = format!(
        "{:<24} {:<24} {:<8} EXPIRES\n",
        "ORGANIZATION", "SLUG", "ROLE"
    );
    for invitation in invitations {
        output.push_str(&format!(
            "{:<24} {:<24} {:<8} {}\n",
            invitation.org_name, invitation.org_slug, invitation.role, invitation.expires_at
        ));
    }
    output
}

fn print_members(members: &[Member], output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(members)?),
        OutputFormat::Text => print!("{}", format_members_text(members)),
    }
    Ok(())
}

fn format_members_text(members: &[Member]) -> String {
    let mut output = format!("{:<32} {:<24} {:<8} USER ID\n", "EMAIL", "NAME", "ROLE");
    for member in members {
        output.push_str(&format!(
            "{:<32} {:<24} {:<8} {}\n",
            member.email,
            member.name.as_deref().unwrap_or("-"),
            member.role,
            member.user_id
        ));
    }
    output
}

/// Removes the member `user` names (a user ID, or an email address ignoring
/// case) once `confirm` agrees, and returns them; `None` when declined. The
/// server decides who may be removed, and its refusal is the error.
async fn remove_member(
    client: &OrganizationClient,
    org_id: &str,
    user: &str,
    confirm: impl FnOnce(&Member) -> anyhow::Result<bool>,
) -> anyhow::Result<Option<Member>> {
    let user = user.trim();
    let members = client.list_members(org_id).await.context("list members")?;
    let member = members
        .into_iter()
        .find(|member| member.user_id == user || member.email.eq_ignore_ascii_case(user))
        .ok_or_else(|| {
            anyhow::anyhow!("no member {user:?} in this organization; `cw org members` lists them")
        })?;
    if !confirm(&member)? {
        eprintln!("Not removed.");
        return Ok(None);
    }
    client
        .remove_member(org_id, &member.user_id)
        .await
        .context("remove member")?;
    Ok(Some(member))
}

/// Waits briefly for a new invitation's email and says what became of it.
/// The one-time link is already printed and stays the fallback.
async fn report_invitation_email(
    client: &OrganizationClient,
    org_id: &str,
    created: &CreatedInvitation,
) -> String {
    let outcome = if created.email_queued {
        client
            .invitation_email(org_id, &created.invitation.id)
            .await
    } else {
        InvitationEmail::NotOffered
    };
    invitation_email_message(&created.invitation.email, &outcome)
}

fn invitation_email_message(email: &str, outcome: &InvitationEmail) -> String {
    const ONCE: &str = "the link is shown only once";
    match outcome {
        InvitationEmail::Sent => {
            format!("Invitation email sent to {email}. The link also works; {ONCE}.")
        }
        InvitationEmail::NotSent { reason } => {
            format!(
                "Email not sent: {reason}; share the link instead. {}.",
                capitalized(ONCE)
            )
        }
        InvitationEmail::Retrying { reason } => format!(
            "Email not sent yet: {reason}; it will be retried. Share the link if it does not arrive; {ONCE}."
        ),
        InvitationEmail::Queued => format!(
            "The invitation email to {email} is not sent yet; share the link if it does not arrive. {}.",
            capitalized(ONCE)
        ),
        InvitationEmail::NotOffered => format!("Share the link; {ONCE}."),
        InvitationEmail::Unknown { reason } => format!(
            "Could not check the invitation email ({reason}); share the link if it does not arrive. {}.",
            capitalized(ONCE)
        ),
    }
}

fn capitalized(text: &str) -> String {
    let mut characters = text.chars();
    characters
        .next()
        .map(|first| first.to_uppercase().chain(characters).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
