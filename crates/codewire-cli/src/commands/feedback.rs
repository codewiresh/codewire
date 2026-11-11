//! `cw feedback` (#4061): send the Codewire team a message, signed in or
//! anonymously. It says which before sending and sends nothing unconfirmed.

use std::io::Read;

use codewire_client::{
    ClientConfig, ErrorCode, FeedbackClient, FeedbackPlacement, SubmitFeedbackRequest,
};

use super::*;
use crate::commands::progress::terminal_text;
use crate::config::selection::{self, SelectionLocation};
use crate::output::{Capabilities, OutputMode, run_message_input};

/// The most a message may hold, in bytes of UTF-8 (10 KB); the server
/// enforces the same limit.
pub(crate) const MAX_FEEDBACK_BYTES: usize = 10 * 1024;
const MAX_ENVIRONMENT_ID_BYTES: usize = 128;

pub(crate) const FEEDBACK_LONG_ABOUT: &str = "Send a message to the Codewire team.

  cw feedback \"MESSAGE\"
  cw feedback                         type it here: Enter starts a new line,
                                      Ctrl-D sends, Esc or Ctrl-C cancels
  some-command | cw feedback --yes    read it from stdin

What is sent, and nothing else:
  - your message, at most 10 KB;
  - this cw's version, your operating system and architecture;
  - whether you work locally or in the cloud (from --local or --cloud, else
    the selected environment);
  - with --environment ID, that environment's ID.
No logs, files, environment contents or settings are sent. Do not paste
secrets into the message.

Signed in, the feedback records your account and your current organization.
Signed out, or with --anonymous, it records neither. Your network address is
never stored: only a keyed hash of it, which limits how much one address can
send. Only Codewire's platform admins can read feedback.

cw says whether it will send signed in or anonymously and asks before
sending; --yes sends without asking. Sending is limited to 10 an hour signed
in and 5 an hour anonymously; a refusal says when to try again.";

#[derive(Debug, Args)]
pub(crate) struct FeedbackArgs {
    #[arg(
        value_name = "MESSAGE",
        num_args = 0..,
        help = "The message; without it, type it in the terminal or pipe it on stdin"
    )]
    message: Vec<String>,
    #[arg(long, help = "Send without your account or organization")]
    anonymous: bool,
    #[arg(
        long,
        value_name = "ID",
        help = "An environment the feedback is about; only its ID is sent"
    )]
    environment: Option<String>,
    #[arg(short, long, help = "Send without asking for confirmation")]
    yes: bool,
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,
}

/// Where the message comes from.
#[derive(Debug, PartialEq, Eq)]
enum MessageSource {
    Argument(String),
    Terminal,
    Stdin,
}

fn message_source(words: &[String], stdin_is_terminal: bool) -> MessageSource {
    if !words.is_empty() {
        MessageSource::Argument(words.join(" "))
    } else if stdin_is_terminal {
        MessageSource::Terminal
    } else {
        MessageSource::Stdin
    }
}

/// Reads at most [`MAX_FEEDBACK_BYTES`] of UTF-8, refusing anything longer
/// rather than cutting it.
fn read_limited(reader: impl Read) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_FEEDBACK_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read the message from stdin")?;
    anyhow::ensure!(
        bytes.len() <= MAX_FEEDBACK_BYTES,
        "the message is longer than 10 KB ({MAX_FEEDBACK_BYTES} bytes); shorten it"
    );
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("the message on stdin is not UTF-8"))
}

/// The message as it is sent: without trailing whitespace, not empty, at
/// most [`MAX_FEEDBACK_BYTES`].
fn checked_message(message: &str) -> anyhow::Result<String> {
    let message = message.trim_end();
    anyhow::ensure!(
        !message.trim().is_empty(),
        "the message is empty; nothing was sent"
    );
    anyhow::ensure!(
        message.len() <= MAX_FEEDBACK_BYTES,
        "the message is {} bytes, longer than 10 KB ({MAX_FEEDBACK_BYTES} bytes); shorten it",
        message.len()
    );
    Ok(message.to_owned())
}

/// The same rule the server applies to an environment ID.
fn checked_environment_id(id: &str) -> anyhow::Result<String> {
    let id = id.trim();
    let valid = (1..=MAX_ENVIRONMENT_ID_BYTES).contains(&id.len())
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    anyhow::ensure!(
        valid,
        "--environment must be an environment ID: letters, digits, '.', '_' or '-'"
    );
    Ok(id.to_owned())
}

/// Local or cloud: the explicit flag, else where the selected environment
/// runs, else unknown.
fn feedback_placement(
    explicit: Option<EnvironmentPlacement>,
    selected: Option<SelectionLocation>,
) -> FeedbackPlacement {
    match (explicit, selected) {
        (Some(EnvironmentPlacement::Local), _) | (None, Some(SelectionLocation::Local)) => {
            FeedbackPlacement::FEEDBACK_PLACEMENT_LOCAL
        }
        (Some(EnvironmentPlacement::Platform), _) | (None, Some(SelectionLocation::Cloud)) => {
            FeedbackPlacement::FEEDBACK_PLACEMENT_CLOUD
        }
        (None, Some(SelectionLocation::Host) | None) => {
            FeedbackPlacement::FEEDBACK_PLACEMENT_UNSPECIFIED
        }
    }
}

fn placement_label(placement: FeedbackPlacement) -> Option<&'static str> {
    match placement {
        FeedbackPlacement::FEEDBACK_PLACEMENT_LOCAL => Some("local"),
        FeedbackPlacement::FEEDBACK_PLACEMENT_CLOUD => Some("cloud"),
        _ => None,
    }
}

/// Who the feedback is from.
#[derive(Debug)]
enum Sender {
    SignedIn {
        platform: config::ResolvedPlatformConfig,
        /// The account as the user knows it.
        account: String,
        /// The current organization's ID and name, when there is one.
        organization: Option<(String, String)>,
    },
    Anonymous {
        server_url: String,
        chosen: bool,
    },
}

impl Sender {
    fn server_url(&self) -> &str {
        match self {
            Self::SignedIn { platform, .. } => &platform.server_url,
            Self::Anonymous { server_url, .. } => server_url,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::SignedIn {
                account,
                organization: Some((_, name)),
                ..
            } => format!("{account}, organization {name}"),
            Self::SignedIn { account, .. } => format!("{account} (no current organization)"),
            Self::Anonymous { chosen: true, .. } => {
                "anonymous (--anonymous): no account or organization".to_owned()
            }
            Self::Anonymous { chosen: false, .. } => {
                "anonymous (not signed in): no account or organization".to_owned()
            }
        }
    }
}

/// The server an anonymous sender reaches: `--server`, else
/// `CODEWIRE_SERVER_URL`, else the saved server, else Codewire's.
fn anonymous_server_url(globals: &Globals, paths: &ResolvePaths, env: &impl config::Env) -> String {
    globals
        .server
        .clone()
        .or_else(|| env.var(config::CODEWIRE_SERVER_URL_ENV))
        .map(|url| config::normalize_server_url(&url))
        .filter(|url| !url.is_empty())
        .or_else(|| {
            config::load_platform_config(&paths.platform_config_dir)
                .ok()
                .map(|saved| config::normalize_server_url(&saved.server_url))
                .filter(|url| !url.is_empty())
        })
        .unwrap_or_else(|| codewire_client::DEFAULT_CODEWIRE_URL.to_owned())
}

fn not_signed_in(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<config::ConfigError>(),
        Some(
            config::ConfigError::NoPlatformServer { .. }
                | config::ConfigError::NoPlatformToken { .. }
                | config::ConfigError::PlatformServerMismatch { .. }
        )
    )
}

fn sign_in_unconfirmed(error: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "could not confirm your sign-in ({error}); nothing was sent. Run `cw login`, or send it anonymously with --anonymous"
    )
}

async fn resolve_sender(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &OsEnv,
    anonymous: bool,
) -> anyhow::Result<Sender> {
    if anonymous {
        return Ok(Sender::Anonymous {
            server_url: anonymous_server_url(globals, paths, env),
            chosen: true,
        });
    }
    let platform = match resolve_platform(globals, paths, env) {
        Ok(platform) => platform,
        Err(error) if not_signed_in(&error) => {
            return Ok(Sender::Anonymous {
                server_url: anonymous_server_url(globals, paths, env),
                chosen: false,
            });
        }
        Err(error) => return Err(error),
    };
    // Listing organizations both proves the credential still works and
    // names the current one.
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .map_err(sign_in_unconfirmed)?;
    let organization = current_org_id(&platform, &orgs).ok().and_then(|id| {
        orgs.iter()
            .find(|org| org.id == id)
            .map(|org| (org.id.clone(), org.name.clone()))
    });
    let account = if platform.oauth_credentials_path.is_some() {
        let token = platform
            .token_provider()?
            .token()
            .await
            .map_err(sign_in_unconfirmed)?;
        codewire_client::OAuthClient::for_server_url(&platform.server_url)?
            .userinfo(&token)
            .await
            .ok()
            .and_then(|user| user.email.filter(|email| !email.is_empty()))
            .unwrap_or_else(|| "your account".to_owned())
    } else {
        format!("the API key in {}", config::CODEWIRE_API_KEY_ENV)
    };
    Ok(Sender::SignedIn {
        platform,
        account,
        organization,
    })
}

fn request(
    message: String,
    placement: FeedbackPlacement,
    environment_id: Option<String>,
    sender: &Sender,
) -> SubmitFeedbackRequest {
    SubmitFeedbackRequest {
        message,
        cli_version: CLI_VERSION.to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        placement: placement.into(),
        environment_id,
        org_id: match sender {
            Sender::SignedIn {
                organization: Some((id, _)),
                ..
            } => Some(id.clone()),
            _ => None,
        },
        ..Default::default()
    }
}

/// What cw shows before asking: who sends, and everything attached.
fn summary(sender: &Sender, request: &SubmitFeedbackRequest) -> String {
    let mut attached = vec![
        format!("cw {}", request.cli_version),
        format!("{} {}", request.os, request.arch),
    ];
    if let Some(placement) = request.placement.as_known().and_then(placement_label) {
        attached.push(placement.to_owned());
    }
    if let Some(id) = &request.environment_id {
        attached.push(format!("environment {id}"));
    }
    format!(
        "Feedback for the Codewire team at {}\n  From      {}\n  Attached  {}\n  Message   {} bytes\n",
        terminal_text(sender.server_url()),
        terminal_text(&sender.describe()),
        terminal_text(&attached.join(", ")),
        request.message.len()
    )
}

pub(crate) async fn handle_feedback_command(
    globals: &Globals,
    args: FeedbackArgs,
) -> anyhow::Result<()> {
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let environment_id = args
        .environment
        .as_deref()
        .map(checked_environment_id)
        .transpose()?;
    let stdin_is_terminal = std::io::stdin().is_terminal();
    let raw = match message_source(&args.message, stdin_is_terminal) {
        MessageSource::Argument(message) => message,
        MessageSource::Stdin => read_limited(std::io::stdin().lock())?,
        MessageSource::Terminal => {
            anyhow::ensure!(
                matches!(args.output, OutputFormat::Text),
                "with -o json, pass the message as an argument or on stdin"
            );
            eprintln!(
                "Do not paste secrets. Only the message and the details cw shows next are sent."
            );
            run_message_input(
                "Feedback for the Codewire team",
                MAX_FEEDBACK_BYTES,
                &Capabilities::from_process(OutputMode::Text),
            )?
            .ok_or_else(|| anyhow::anyhow!("canceled; no feedback sent"))?
        }
    };
    let message = checked_message(&raw)?;

    let sender = resolve_sender(globals, &paths, &env, args.anonymous).await?;
    let selected = selection::load(&paths.mesh_data_dir)
        .ok()
        .flatten()
        .map(|selected| selected.location);
    let placement = feedback_placement(globals.placement, selected);
    let request = request(message, placement, environment_id, &sender);

    eprint!("{}", summary(&sender, &request));
    if !args.yes {
        anyhow::ensure!(
            matches!(args.output, OutputFormat::Text)
                && stdin_is_terminal
                && super::guided::available(OutputFormat::Text),
            "not sent: confirm in an interactive terminal, or pass --yes to send without asking"
        );
        let confirmed = super::guided::confirm("Send this feedback?")
            .map_err(|_| anyhow::anyhow!("canceled; no feedback sent"))?;
        anyhow::ensure!(confirmed, "canceled; no feedback sent");
    }

    let config = ClientConfig::new(sender.server_url())?
        .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
    let client = match &sender {
        Sender::SignedIn { platform, .. } => {
            FeedbackClient::signed_in(config, platform.token_provider()?)?
        }
        Sender::Anonymous { .. } => FeedbackClient::anonymous(config)?,
    };
    let response = client
        .submit_feedback(request)
        .await
        .map_err(|error| match error.code() {
            ErrorCode::ResourceExhausted => anyhow::anyhow!("not sent: {}", error.message()),
            ErrorCode::Unauthenticated => sign_in_unconfirmed(error.message()),
            _ => anyhow::Error::from(error).context("send feedback"),
        })?;
    match args.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "id": response.id,
                "signed_in": response.signed_in,
            }))?
        ),
        OutputFormat::Text => println!("Feedback sent ({}). Thank you.", response.id),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &[&str]) -> Vec<String> {
        text.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn the_message_comes_from_the_arguments_then_the_terminal_then_stdin() {
        assert_eq!(
            message_source(&words(&["works", "well"]), true),
            MessageSource::Argument("works well".into())
        );
        assert_eq!(message_source(&[], true), MessageSource::Terminal);
        assert_eq!(message_source(&[], false), MessageSource::Stdin);
    }

    #[test]
    fn stdin_is_read_up_to_10_kb_and_refused_beyond() {
        let exact = "x".repeat(MAX_FEEDBACK_BYTES);
        assert_eq!(read_limited(exact.as_bytes()).unwrap(), exact);
        let error = read_limited("x".repeat(MAX_FEEDBACK_BYTES + 1).as_bytes()).unwrap_err();
        assert!(error.to_string().contains("longer than 10 KB"), "{error}");
        assert!(read_limited(&[0xff, 0xfe][..]).is_err());
    }

    #[test]
    fn a_message_is_trimmed_at_the_end_and_must_say_something() {
        assert_eq!(checked_message("  hi\nthere\n\n").unwrap(), "  hi\nthere");
        assert!(checked_message(" \n\t").is_err());
        assert!(checked_message(&"é".repeat(5121)).is_err());
        assert!(checked_message(&format!("{}\n", "é".repeat(5120))).is_ok());
    }

    #[test]
    fn an_environment_id_follows_the_server_rule() {
        assert_eq!(
            checked_environment_id(" 8f0c2b3e-1a2b ").unwrap(),
            "8f0c2b3e-1a2b"
        );
        for invalid in ["", "-x", "a b", "a/b", &"a".repeat(129)] {
            assert!(checked_environment_id(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn placement_is_the_flag_then_the_selected_environment() {
        use FeedbackPlacement::*;
        assert_eq!(
            feedback_placement(
                Some(EnvironmentPlacement::Local),
                Some(SelectionLocation::Cloud)
            ),
            FEEDBACK_PLACEMENT_LOCAL
        );
        assert_eq!(
            feedback_placement(Some(EnvironmentPlacement::Platform), None),
            FEEDBACK_PLACEMENT_CLOUD
        );
        assert_eq!(
            feedback_placement(None, Some(SelectionLocation::Cloud)),
            FEEDBACK_PLACEMENT_CLOUD
        );
        assert_eq!(
            feedback_placement(None, Some(SelectionLocation::Host)),
            FEEDBACK_PLACEMENT_UNSPECIFIED
        );
        assert_eq!(
            feedback_placement(None, None),
            FEEDBACK_PLACEMENT_UNSPECIFIED
        );
    }

    #[test]
    fn the_summary_names_the_sender_and_everything_attached() {
        let sender = Sender::Anonymous {
            server_url: "https://codewire.example".into(),
            chosen: true,
        };
        let request = request(
            "hello".into(),
            FeedbackPlacement::FEEDBACK_PLACEMENT_CLOUD,
            Some("env-1".into()),
            &sender,
        );
        assert_eq!(request.org_id, None);
        assert_eq!(request.cli_version, CLI_VERSION);
        let text = summary(&sender, &request);
        assert!(text.contains("at https://codewire.example\n"), "{text}");
        assert!(
            text.contains("From      anonymous (--anonymous): no account or organization\n"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "Attached  cw {CLI_VERSION}, {} {}, cloud, environment env-1\n",
                std::env::consts::OS,
                std::env::consts::ARCH
            )),
            "{text}"
        );
        assert!(text.contains("Message   5 bytes\n"), "{text}");
    }

    #[test]
    fn a_signed_in_sender_sends_its_current_organization() {
        let sender = Sender::SignedIn {
            platform: config::ResolvedPlatformConfig::static_token(
                "https://codewire.example",
                "cw_synthetic",
                false,
                None,
            ),
            account: "alice@example.test".into(),
            organization: Some(("org-1".into(), "Acme".into())),
        };
        let request = request(
            "hi".into(),
            FeedbackPlacement::FEEDBACK_PLACEMENT_UNSPECIFIED,
            None,
            &sender,
        );
        assert_eq!(request.org_id.as_deref(), Some("org-1"));
        let text = summary(&sender, &request);
        assert!(
            text.contains("From      alice@example.test, organization Acme\n"),
            "{text}"
        );
        assert!(!text.contains("environment"), "{text}");
    }

    #[test]
    fn the_help_says_exactly_what_is_sent() {
        for fragment in [
            "your message, at most 10 KB",
            "this cw's version, your operating system and architecture",
            "whether you work locally or in the cloud",
            "with --environment ID, that environment's ID",
            "No logs, files, environment contents or settings are sent",
            "Do not paste\nsecrets",
            "Only Codewire's platform admins can read feedback",
            "--yes sends without asking",
        ] {
            assert!(FEEDBACK_LONG_ABOUT.contains(fragment), "{fragment}");
        }
    }
}
