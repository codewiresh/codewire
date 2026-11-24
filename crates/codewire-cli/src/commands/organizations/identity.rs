//! `cw identity`: sandbox identity (docs/dev/SANDBOX-IDENTITY.md). An
//! organization's owners and admins set each Sandbox's identity groups,
//! register the audiences its Sandboxes may get tokens for, and stop or
//! resume minting.

use codewire_client::ClientError;
use codewire_client::sandbox_identity::{
    EnvironmentIdentityGroups, GetEnvironmentIdentityGroupsRequest, IdentityAudience,
    IdentityAudienceGroups, IdentityGroupUser, IdentityGroupUserReason,
    ListIdentityAudiencesRequest, RegisterIdentityAudienceRequest, RemoveIdentityAudienceRequest,
    ResumeIdentityMintingRequest, SetEnvironmentIdentityGroupsRequest, StopIdentityMintingRequest,
};
use serde_json::json;

use super::*;
use crate::commands::progress::terminal_text;
use crate::output::{Capabilities, OutputMode, Status, Style, render_next};

pub(crate) const IDENTITY_LONG_ABOUT: &str = "Sandbox identity: short-lived tokens a cloud Sandbox gets to prove which organization's Sandbox it is, for one verifier the organization registered.\n\nAn organization's owners and admins set each Sandbox's identity groups, register audiences, and stop or resume minting. Inside a cloud Sandbox, `cw identity token --resource URI` prints a token.\n\n  cw identity groups app\n  cw identity groups set app data-readers\n  cw identity audience add https://k8s.example.com --lifetime 5m\n  cw identity audience list\n  cw identity stop app\n  cw identity resume app\n  cw identity token --resource https://k8s.example.com";

#[derive(Debug, Args)]
pub(crate) struct IdentityArgs {
    #[command(subcommand)]
    pub(crate) command: IdentityCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IdentityCommand {
    #[command(about = "Show a Sandbox's identity groups; `set` replaces them")]
    Groups(IdentityGroupsArgs),
    #[command(
        subcommand,
        about = "Register, list and remove the verifiers tokens are for"
    )]
    Audience(IdentityAudienceCommand),
    #[command(about = "Stop minting tokens for a Sandbox, or the whole organization")]
    Stop(IdentityMintingArgs),
    #[command(about = "Resume minting tokens for a Sandbox, or the whole organization")]
    Resume(IdentityMintingArgs),
    #[command(
        about = "Print this Sandbox's token for one audience; inside a cloud Sandbox only",
        long_about = "Print this Sandbox's identity token for one audience its organization registered, on standard output with no newline. Inside a cloud Sandbox only; it needs no sign-in or organization.\n\n  kubectl --token \"$(cw identity token --resource https://k8s.example.com)\" get pods"
    )]
    Token(crate::identity_token::IdentityTokenArgs),
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub(crate) struct IdentityGroupsArgs {
    #[command(subcommand)]
    pub(crate) command: Option<IdentityGroupsCommand>,
    #[arg(
        value_name = "ENV",
        required = true,
        help = "The Sandbox, by name or ID"
    )]
    pub(crate) environment: Option<String>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IdentityGroupsCommand {
    #[command(
        about = "Replace a Sandbox's identity groups; --clear removes them all",
        after_help = "Everyone who can run code in the Sandbox can use its groups: its creator, members granted operator or owner, the organization's owners and admins, and every process in it. The command lists them.\n\nA group name is 1 to 63 lowercase letters, digits and hyphens; `all` is reserved. A Sandbox has at most 32."
    )]
    Set(IdentityGroupsSetArgs),
}

#[derive(Debug, Args)]
#[command(group = clap::ArgGroup::new("new_groups").required(true).args(["groups", "clear"]))]
pub(crate) struct IdentityGroupsSetArgs {
    #[arg(value_name = "ENV", help = "The Sandbox, by name or ID")]
    pub(crate) environment: String,
    #[arg(
        value_name = "GROUP",
        help = "The Sandbox's groups, replacing those it has"
    )]
    pub(crate) groups: Vec<String>,
    #[arg(long, conflicts_with = "groups", help = "Remove every group")]
    pub(crate) clear: bool,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IdentityAudienceCommand {
    #[command(
        about = "Register a verifier: an https URI tokens may name as their audience",
        after_help = "Examples:\n  cw identity audience add https://k8s.example.com\n  cw identity audience add https://vault.example.com:8200/v1/auth/jwt --groups readers --lifetime 5m --file vault\n\nThe audience is stored in its canonical form: lowercase scheme and host, no :443, and the path exactly as written. It can't be an IP address, a local or private-network name, the in-cluster Kubernetes API, or a domain this deployment serves."
    )]
    Add(IdentityAudienceAddArgs),
    #[command(
        visible_alias = "ls",
        about = "List the organization's registered audiences"
    )]
    List(IdentityAudienceListArgs),
    #[command(visible_alias = "rm", about = "Remove a registered audience")]
    Remove(IdentityAudienceRemoveArgs),
}

/// A claim a registration may add to its tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum IdentityClaim {
    #[value(name = "created_by")]
    CreatedBy,
    #[value(name = "environment_name")]
    EnvironmentName,
}

#[derive(Debug, Args)]
pub(crate) struct IdentityAudienceAddArgs {
    #[arg(value_name = "URI", help = "The verifier's audience, an https URI")]
    pub(crate) audience: String,
    #[arg(
        long,
        value_name = "GROUP",
        value_delimiter = ',',
        help = "Only these of a Sandbox's groups go in its tokens (default: every group)"
    )]
    pub(crate) groups: Option<Vec<String>>,
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_lifetime,
        help = "How long a token lives, 1m to 10m (default 10m)"
    )]
    pub(crate) lifetime: Option<u32>,
    #[arg(
        long,
        value_enum,
        help = "Add this claim to its tokens; repeat for both"
    )]
    pub(crate) claim: Vec<IdentityClaim>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Keep a current token in /codewire/run/identity/NAME.jwt in each Sandbox"
    )]
    pub(crate) file: Option<String>,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct IdentityAudienceListArgs {
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct IdentityAudienceRemoveArgs {
    #[arg(
        value_name = "URI",
        help = "The registered audience, in any spelling of it"
    )]
    pub(crate) audience: String,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Debug, Args)]
#[command(group = clap::ArgGroup::new("target").required(true).args(["environment", "org"]))]
pub(crate) struct IdentityMintingArgs {
    #[arg(value_name = "ENV", help = "The Sandbox, by name or ID")]
    pub(crate) environment: Option<String>,
    #[arg(long, help = "Every Sandbox in the current organization")]
    pub(crate) org: bool,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

/// `--lifetime`: whole minutes or seconds, such as `10m` or `90s`. The
/// server holds it to 1 to 10 minutes.
fn parse_lifetime(raw: &str) -> Result<u32, String> {
    let invalid =
        || format!("{raw:?} is not a lifetime: use minutes or seconds, such as 10m or 90s");
    let (number, multiplier) = match (raw.strip_suffix('m'), raw.strip_suffix('s')) {
        (Some(minutes), _) => (minutes, 60),
        (_, Some(seconds)) => (seconds, 1),
        _ => return Err(invalid()),
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    number
        .parse::<u32>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .ok_or_else(invalid)
}

pub(crate) async fn handle_identity_command(
    globals: &Globals,
    args: IdentityArgs,
) -> anyhow::Result<()> {
    match args.command {
        IdentityCommand::Groups(args) => match args.command {
            Some(IdentityGroupsCommand::Set(set)) => set_groups(globals, set).await,
            None => {
                let environment = args.environment.context("name the Sandbox: ENV")?;
                show_groups(globals, &environment, args.output).await
            }
        },
        IdentityCommand::Audience(command) => audience(globals, command).await,
        IdentityCommand::Stop(args) => minting(globals, args, Switch::Stop).await,
        IdentityCommand::Resume(args) => minting(globals, args, Switch::Resume).await,
        IdentityCommand::Token(args) => crate::identity_token::identity_token(args).await,
    }
}

/// A failed call, in the user's terms: the server's own refusal names the
/// rule a request broke.
fn failed(action: &str, error: ClientError) -> anyhow::Error {
    anyhow::anyhow!("couldn't {action}: {}", error.message())
}

fn print_json(value: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn stdout_style() -> Style {
    Capabilities::from_process(OutputMode::Text).stdout_style()
}

/// The org and the Sandbox `environment` names in it.
async fn sandbox(globals: &Globals, environment: &str) -> anyhow::Result<(String, String)> {
    let (org_id, _, environments) = resolve_platform_context(globals).await?;
    let environment_id = resolve_environment_id(&environments, &org_id, environment).await?;
    Ok((org_id, environment_id))
}

async fn show_groups(
    globals: &Globals,
    environment: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let (org_id, environment_id) = sandbox(globals, environment).await?;
    let client = super::super::guided_credentials::platform_client(globals)?;
    let groups = client
        .get_environment_identity_groups(GetEnvironmentIdentityGroupsRequest {
            org_id,
            environment_id,
            ..Default::default()
        })
        .await
        .map_err(|error| failed("read the identity groups", error))?
        .groups
        .into_option()
        .unwrap_or_default();
    match output {
        OutputFormat::Json => print_json(&groups_json(&groups)),
        OutputFormat::Text => {
            print!(
                "{}",
                groups_text(environment, &groups.groups, stdout_style())
            );
            Ok(())
        }
    }
}

fn groups_json(groups: &EnvironmentIdentityGroups) -> serde_json::Value {
    json!({
        "environment_id": groups.environment_id,
        "groups": groups.groups,
        "version": groups.version,
    })
}

/// One group a line, or the empty state and the command that fills it.
fn groups_text(environment: &str, groups: &[String], style: Style) -> String {
    let environment = terminal_text(environment);
    if groups.is_empty() {
        return format!(
            "{environment} has no identity groups.\n{}",
            render_next(
                &format!("cw identity groups set {environment} GROUP…"),
                style
            )
        );
    }
    groups.iter().map(|group| format!("{group}\n")).collect()
}

async fn set_groups(globals: &Globals, args: IdentityGroupsSetArgs) -> anyhow::Result<()> {
    let (org_id, environment_id) = sandbox(globals, &args.environment).await?;
    let client = super::super::guided_credentials::platform_client(globals)?;
    let groups = if args.clear { Vec::new() } else { args.groups };
    let response = client
        .set_environment_identity_groups(SetEnvironmentIdentityGroupsRequest {
            org_id,
            environment_id,
            groups,
            ..Default::default()
        })
        .await
        .map_err(|error| failed("set the identity groups", error))?;
    let stored = response.groups.into_option().unwrap_or_default();
    match args.output {
        OutputFormat::Json => {
            let mut value = groups_json(&stored);
            value["previous_groups"] = json!(response.previous_groups);
            value["changed"] = json!(response.changed);
            value["can_run_code"] = response
                .can_run_code
                .iter()
                .map(|user| {
                    json!({
                        "user_id": user.user_id,
                        "email": user.email,
                        "reason": reason_name(user),
                    })
                })
                .collect();
            print_json(&value)
        }
        OutputFormat::Text => {
            print!(
                "{}",
                set_groups_text(
                    &args.environment,
                    &stored.groups,
                    response.changed,
                    &response.can_run_code,
                    stdout_style()
                )
            );
            Ok(())
        }
    }
}

fn reason_name(user: &IdentityGroupUser) -> &'static str {
    match user.reason.as_known() {
        Some(IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_CREATOR) => "creator",
        Some(IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_OWNER_GRANT) => "owner",
        Some(IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_OPERATOR_GRANT) => "operator",
        Some(IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_ORGANIZATION_ADMIN) => {
            "organization_admin"
        }
        Some(IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_UNSPECIFIED) | None => "unknown",
    }
}

fn reason_text(user: &IdentityGroupUser) -> &'static str {
    match reason_name(user) {
        "creator" => "created it",
        "owner" => "granted owner",
        "operator" => "granted operator",
        "organization_admin" => "organization owner or admin",
        _ => "can run code",
    }
}

/// The outcome, then who can use the groups: everyone who can run code in
/// the Sandbox, and every process in it (docs/dev/SANDBOX-IDENTITY.md,
/// "What a group means").
fn set_groups_text(
    environment: &str,
    groups: &[String],
    changed: bool,
    can_run_code: &[IdentityGroupUser],
    style: Style,
) -> String {
    let environment = terminal_text(environment);
    let done = style.status(Status::Done);
    let mut text = match (groups.is_empty(), changed) {
        (true, true) => format!("{done} Removed every identity group from {environment}.\n"),
        (true, false) => format!("{environment} has no identity groups.\n"),
        (false, true) => format!(
            "{done} Identity groups of {environment}: {}\n",
            groups.join(", ")
        ),
        (false, false) => format!(
            "{environment} already has these identity groups: {}\n",
            groups.join(", ")
        ),
    };
    if !groups.is_empty() {
        text.push_str(&format!(
            "\nWho can run code in {environment}, and so use these groups:\n"
        ));
        for user in can_run_code {
            text.push_str(&format!(
                "  {}{}{}\n",
                terminal_text(&user.email),
                style.separator(),
                reason_text(user)
            ));
        }
        text.push_str(&format!("  and every process running in {environment}.\n"));
    }
    if changed {
        text.push_str(
            "\nThe next token has the change. Tokens already issued keep their groups until they expire, within 10 minutes.\n",
        );
    }
    text
}

async fn audience(globals: &Globals, command: IdentityAudienceCommand) -> anyhow::Result<()> {
    let (org_id, _, _) = resolve_platform_context(globals).await?;
    let client = super::super::guided_credentials::platform_client(globals)?;
    match command {
        IdentityAudienceCommand::Add(args) => {
            let registered = client
                .register_identity_audience(RegisterIdentityAudienceRequest {
                    org_id,
                    audience: args.audience,
                    visible_groups: args
                        .groups
                        .map(|names| IdentityAudienceGroups {
                            names,
                            ..Default::default()
                        })
                        .into(),
                    lifetime: args
                        .lifetime
                        .map(|seconds| {
                            codewire_client::ProtoDuration::from_secs(i64::from(seconds))
                        })
                        .into(),
                    claim_created_by: args.claim.contains(&IdentityClaim::CreatedBy),
                    claim_environment_name: args.claim.contains(&IdentityClaim::EnvironmentName),
                    file_name: args.file,
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("register the audience", error))?
                .audience
                .into_option()
                .context("the server answered without the registration")?;
            match args.output {
                OutputFormat::Json => print_json(&audience_json(&registered)),
                OutputFormat::Text => {
                    print!("{}", registered_text(&registered, stdout_style()));
                    Ok(())
                }
            }
        }
        IdentityAudienceCommand::List(args) => {
            let audiences = client
                .list_identity_audiences(ListIdentityAudiencesRequest {
                    org_id,
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("list the audiences", error))?
                .audiences;
            match args.output {
                OutputFormat::Json => print_json(&audiences.iter().map(audience_json).collect()),
                OutputFormat::Text => {
                    print!("{}", audiences_text(&audiences, stdout_style()));
                    Ok(())
                }
            }
        }
        IdentityAudienceCommand::Remove(args) => {
            let removed = client
                .remove_identity_audience(RemoveIdentityAudienceRequest {
                    org_id,
                    audience: args.audience,
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("remove the audience", error))?
                .audience;
            match args.output {
                OutputFormat::Json => print_json(&json!({ "audience": removed })),
                OutputFormat::Text => {
                    println!(
                        "{} Removed {}. Sandboxes get no new token for it.",
                        stdout_style().status(Status::Done),
                        terminal_text(&removed)
                    );
                    Ok(())
                }
            }
        }
    }
}

fn lifetime_seconds(audience: &IdentityAudience) -> i64 {
    audience
        .lifetime
        .as_option()
        .map_or(600, |lifetime| lifetime.seconds)
}

fn lifetime_text(seconds: i64) -> String {
    if seconds % 60 == 0 {
        let minutes = seconds / 60;
        format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
    } else {
        format!("{seconds} seconds")
    }
}

fn visible_groups_text(audience: &IdentityAudience) -> String {
    match audience.visible_groups.as_option() {
        None => "every group".to_owned(),
        Some(groups) if groups.names.is_empty() => "none but all".to_owned(),
        Some(groups) => groups.names.join(", "),
    }
}

fn claims(audience: &IdentityAudience) -> Vec<&'static str> {
    let mut claims = Vec::new();
    if audience.claim_created_by {
        claims.push("created_by");
    }
    if audience.claim_environment_name {
        claims.push("environment_name");
    }
    claims
}

fn audience_json(audience: &IdentityAudience) -> serde_json::Value {
    json!({
        "audience": audience.audience,
        "visible_groups": audience.visible_groups.as_option().map(|groups| groups.names.clone()),
        "lifetime_seconds": lifetime_seconds(audience),
        "claims": claims(audience),
        "file_name": audience.file_name,
        "version": audience.version,
    })
}

fn registered_text(audience: &IdentityAudience, style: Style) -> String {
    let claims = claims(audience);
    let mut text = format!(
        "{} Registered {}\n  Groups:    {}\n  Lifetime:  {}\n  Claims:    {}\n",
        style.status(Status::Done),
        terminal_text(&audience.audience),
        terminal_text(&visible_groups_text(audience)),
        lifetime_text(lifetime_seconds(audience)),
        if claims.is_empty() {
            "none".to_owned()
        } else {
            claims.join(", ")
        },
    );
    if let Some(file) = &audience.file_name {
        text.push_str(&format!(
            "  File:      /codewire/run/identity/{}.jwt\n",
            terminal_text(file)
        ));
    }
    text
}

fn audiences_text(audiences: &[IdentityAudience], style: Style) -> String {
    if audiences.is_empty() {
        return format!(
            "No audiences are registered.\n{}",
            render_next("cw identity audience add URI", style)
        );
    }
    let rows: Vec<[String; 4]> = audiences
        .iter()
        .map(|audience| {
            [
                terminal_text(&audience.audience),
                lifetime_text(lifetime_seconds(audience)),
                terminal_text(&visible_groups_text(audience)),
                audience
                    .file_name
                    .as_deref()
                    .map_or_else(|| "-".to_owned(), terminal_text),
            ]
        })
        .collect();
    let headings = ["AUDIENCE", "LIFETIME", "GROUPS", "FILE"];
    let widths: Vec<usize> = (0..3)
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .chain([headings[column].len()])
                .max()
                .unwrap_or_default()
        })
        .collect();
    std::iter::once(headings.map(str::to_owned))
        .chain(rows)
        .map(|row| {
            format!(
                "{:<w0$}  {:<w1$}  {:<w2$}  {}\n",
                row[0],
                row[1],
                row[2],
                row[3],
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2],
            )
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Switch {
    Stop,
    Resume,
}

async fn minting(
    globals: &Globals,
    args: IdentityMintingArgs,
    switch: Switch,
) -> anyhow::Result<()> {
    let (org_id, environment_id) = match &args.environment {
        Some(environment) if !args.org => sandbox(globals, environment).await?,
        _ => (resolve_platform_context(globals).await?.0, String::new()),
    };
    let client = super::super::guided_credentials::platform_client(globals)?;
    let changed = match switch {
        Switch::Stop => {
            client
                .stop_identity_minting(StopIdentityMintingRequest {
                    org_id,
                    environment_id,
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("stop minting", error))?
                .changed
        }
        Switch::Resume => {
            client
                .resume_identity_minting(ResumeIdentityMintingRequest {
                    org_id,
                    environment_id,
                    ..Default::default()
                })
                .await
                .map_err(|error| failed("resume minting", error))?
                .changed
        }
    };
    let target = match &args.environment {
        Some(environment) if !args.org => terminal_text(environment),
        _ => "every Sandbox in the organization".to_owned(),
    };
    match args.output {
        OutputFormat::Json => print_json(&json!({ "changed": changed })),
        OutputFormat::Text => {
            print!("{}", minting_text(switch, &target, changed, stdout_style()));
            Ok(())
        }
    }
}

fn minting_text(switch: Switch, target: &str, changed: bool, style: Style) -> String {
    let done = style.status(Status::Done);
    match (switch, changed) {
        (Switch::Stop, true) => format!(
            "{done} Minting stopped for {target}.\nTokens already issued stay valid until they expire, within 10 minutes.\n"
        ),
        (Switch::Stop, false) => format!("Minting was already stopped for {target}.\n"),
        (Switch::Resume, true) => format!("{done} Minting resumed for {target}.\n"),
        (Switch::Resume, false) => format!("Minting was not stopped for {target}.\n"),
    }
}

#[cfg(test)]
mod tests;
