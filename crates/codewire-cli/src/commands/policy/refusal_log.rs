//! `cw --local policy log ENV` (#5058; journey step `refusal-log`): what a
//! running local VM's egress broker refused since it started, one row per
//! destination, protocol, port and reason, most recently seen first, and the
//! one `cw policy` step that would allow the latest refusal a rule can.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;
use codewire_egress_policy::BuiltinPolicy;
use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::record::Destination;
use serde::Serialize;

use crate::commands::OutputFormat;
use crate::output::{Status, Style};

/// How a destination reads when its name failed the host check.
const WITHHELD: &str = "(a name cw won't show)";
/// The narrowest a shortened column gets.
const MIN_SHORTENED: usize = 12;

#[derive(Debug, Args)]
pub(crate) struct PolicyLogArgs {
    #[arg(
        value_name = "ENV",
        help = "The running local VM whose refusals to show"
    )]
    pub(crate) env: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    pub(crate) output: OutputFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Protocol {
    Dns,
    Tcp,
    Udp,
}

impl Protocol {
    fn word(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One row as the CLI shows it, parsed once from the supervisor's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    /// A checked name or an address; `None` when withheld.
    destination: Option<String>,
    named: bool,
    address: Option<String>,
    protocol: Protocol,
    port: Option<u16>,
    reason: RefusalReason,
    policy: Option<(String, u32)>,
    first_unix_ms: i64,
    last_unix_ms: i64,
    count: u64,
}

impl Row {
    /// `None` for a row this cw can't read, which it leaves out.
    fn parse(refusal: &codewire_local_vmm::control::v1::EgressRefusal) -> Option<Self> {
        use codewire_local_vmm::control::v1::EgressRefusalProtocol as Wire;
        use codewire_local_vmm::control::v1::egress_refusal::Destination as WireDestination;
        // The runner checked the name already; it is checked again here, so
        // nothing it holds can reach the terminal.
        let (destination, named) = match refusal.destination.as_ref()? {
            WireDestination::Name(name) => match Destination::checked_name(name) {
                Destination::Name(name) => (Some(name), true),
                Destination::Address(_) | Destination::Withheld => (None, true),
            },
            WireDestination::AddressOnly(address) => (
                Some(address.parse::<std::net::IpAddr>().ok()?.to_string()),
                false,
            ),
            WireDestination::Withheld(_) => (None, true),
        };
        let address = match refusal.address.as_str() {
            "" => None,
            address => Some(address.parse::<std::net::IpAddr>().ok()?.to_string()),
        };
        let (protocol, port) = match (Wire::try_from(refusal.protocol).ok()?, refusal.port) {
            (Wire::Dns, 0) => (Protocol::Dns, None),
            (Wire::Tcp, port) if port != 0 => (Protocol::Tcp, Some(u16::try_from(port).ok()?)),
            (Wire::Udp, port) if port != 0 => (Protocol::Udp, Some(u16::try_from(port).ok()?)),
            _ => return None,
        };
        let reason = RefusalReason::ALL
            .into_iter()
            .find(|reason| reason.code() == refusal.reason)?;
        let policy = Destination::checked_name(&refusal.policy_name);
        let policy = match policy {
            Destination::Name(_) => Some((refusal.policy_name.clone(), refusal.policy_revision)),
            Destination::Address(_) | Destination::Withheld => None,
        };
        Some(Self {
            destination,
            named,
            address,
            protocol,
            port,
            reason,
            policy,
            first_unix_ms: refusal.first_seen_unix_ms,
            last_unix_ms: refusal.last_seen_unix_ms,
            count: refusal.count,
        })
    }

    fn destination_text(&self) -> &str {
        self.destination.as_deref().unwrap_or(WITHHELD)
    }

    fn policy_text(&self) -> String {
        match &self.policy {
            None => "-".to_owned(),
            Some((name, 0)) => name.clone(),
            Some((name, revision)) => format!("{name} · rev {revision}"),
        }
    }

    /// The `cw policy` target that would allow this row, when a rule can:
    /// a name or address not allowed, or a port not allowed. Never a
    /// protected, expired or intercepted one.
    fn allow_target(&self) -> Option<String> {
        if !matches!(
            self.reason,
            RefusalReason::NameNotAllowed
                | RefusalReason::PortNotAllowed
                | RefusalReason::AddressNotAllowed
        ) {
            return None;
        }
        let destination = self.destination.as_deref()?;
        Some(match (self.port, self.named) {
            (None, _) => destination.to_owned(),
            (Some(port), false) if destination.contains(':') => format!("[{destination}]:{port}"),
            (Some(port), _) => format!("{destination}:{port}"),
        })
    }
}

#[derive(Debug, Serialize)]
struct RowJson<'a> {
    destination: Option<&'a str>,
    withheld: bool,
    address: Option<&'a str>,
    port: Option<u16>,
    protocol: Protocol,
    reason: &'a str,
    source: &'static str,
    policy: Option<&'a str>,
    revision: Option<u32>,
    first: String,
    last: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct LogJson<'a> {
    refusals: Vec<RowJson<'a>>,
    dropped: u64,
}

fn rfc3339(unix_ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_ms)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

fn json(rows: &[Row], dropped: u64) -> anyhow::Result<String> {
    let refusals = rows
        .iter()
        .map(|row| RowJson {
            destination: row.destination.as_deref(),
            withheld: row.destination.is_none(),
            address: row.address.as_deref(),
            port: row.port,
            protocol: row.protocol,
            reason: row.reason.code(),
            source: "network",
            policy: row.policy.as_ref().map(|(name, _)| name.as_str()),
            revision: row.policy.as_ref().map(|(_, revision)| *revision),
            first: rfc3339(row.first_unix_ms),
            last: rfc3339(row.last_unix_ms),
            count: row.count,
        })
        .collect();
    Ok(serde_json::to_string_pretty(&LogJson {
        refusals,
        dropped,
    })?)
}

fn ago(unix_ms: i64, now_unix_ms: i64) -> String {
    let seconds = now_unix_ms.saturating_sub(unix_ms).max(0) / 1_000;
    match seconds {
        0..60 => format!("{seconds}s ago"),
        60..3_600 => format!("{}m ago", seconds / 60),
        3_600..86_400 => format!("{}h ago", seconds / 3_600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

/// `text` cut in the middle to `width` characters.
fn shorten_middle(text: &str, width: usize) -> String {
    let length = text.chars().count();
    if length <= width {
        return text.to_owned();
    }
    let keep = width.saturating_sub(1);
    let head = keep.div_ceil(2);
    let tail = keep - head;
    let start: String = text.chars().take(head).collect();
    let end: String = text.chars().skip(length - tail).collect();
    format!("{start}…{end}")
}

const HEADER: [&str; 8] = [
    "DESTINATION",
    "PROTOCOL",
    "PORT",
    "REASON",
    "POLICY",
    "COUNT",
    "FIRST",
    "LAST",
];

/// The table, its column widths from the content and cut to `columns`: the
/// policy column gives way first, then the destination column, which never
/// cuts an address.
fn table(rows: &[Row], now_unix_ms: i64, columns: usize) -> String {
    let mut cells: Vec<[String; 8]> = rows
        .iter()
        .map(|row| {
            [
                row.destination_text().to_owned(),
                row.protocol.word().to_owned(),
                row.port
                    .map_or_else(|| "-".to_owned(), |port| port.to_string()),
                row.reason.description().to_owned(),
                row.policy_text(),
                row.count.to_string(),
                ago(row.first_unix_ms, now_unix_ms),
                ago(row.last_unix_ms, now_unix_ms),
            ]
        })
        .collect();
    let mut widths = HEADER.map(|title| title.chars().count());
    for row in &cells {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let total = |widths: &[usize; 8]| widths.iter().sum::<usize>() + 2 * (widths.len() - 1);
    let widest_address = rows
        .iter()
        .filter(|row| !row.named)
        .map(|row| row.destination_text().chars().count())
        .max()
        .unwrap_or(0);
    for column in [4, 0] {
        let over = total(&widths).saturating_sub(columns);
        let floor = MIN_SHORTENED.max(HEADER[column].len());
        let floor = if column == 0 {
            floor.max(widest_address)
        } else {
            floor
        };
        widths[column] = widths[column]
            .saturating_sub(over)
            .max(floor.min(widths[column]));
    }
    for row in &mut cells {
        for column in [4, 0] {
            row[column] = shorten_middle(&row[column], widths[column]);
        }
    }
    let mut output = String::new();
    let mut line = |cells: [&str; 8]| {
        let mut text = String::new();
        for (index, (cell, width)) in cells.iter().zip(widths).enumerate() {
            if index + 1 == cells.len() {
                text.push_str(cell);
            } else {
                text.push_str(&format!("{cell:<width$}  "));
            }
        }
        output.push_str(text.trim_end());
        output.push('\n');
    };
    line(HEADER);
    for row in &cells {
        line(row.each_ref().map(String::as_str));
    }
    output
}

/// The one step that would allow the most recent refusal a rule can: an
/// edit of the user's own policy, or a new policy from `locked`. Under
/// `open` there is none: `create` refuses `--from open`, and a policy from
/// `locked` would drop the ports `open` allows. A row refused under an older
/// revision of the user's policy gets none either, since an edit since may
/// already allow it; `current` names each policy's current revision.
fn next_step(rows: &[Row], current: &HashMap<String, u32>) -> Option<String> {
    let row = rows
        .iter()
        .find(|row| row.allow_target().is_some() && row.policy.is_some())?;
    let (target, (policy, _)) = (row.allow_target()?, row.policy.as_ref()?);
    match BuiltinPolicy::from_name(policy) {
        Some(BuiltinPolicy::Open) => None,
        Some(BuiltinPolicy::Locked) => Some(format!(
            "cw --local policy create NAME --from locked --allow {target}"
        )),
        None if current.get(policy) == Some(&row.policy.as_ref()?.1) => {
            Some(format!("cw --local policy allow {policy} {target}"))
        }
        None => None,
    }
}

/// The text `cw --local policy log ENV` prints for `rows`, most recently
/// seen first.
fn text(
    environment: &str,
    rows: &[Row],
    dropped: u64,
    now_unix_ms: i64,
    columns: usize,
    style: Style,
    current: &HashMap<String, u32>,
) -> String {
    if rows.is_empty() {
        return format!("Nothing refused since {environment} started.\n");
    }
    let mut output = table(rows, now_unix_ms, columns);
    if dropped > 0 {
        output.push_str(&format!(
            "\n{dropped} {} seen least recently {} dropped; the log keeps the 1,000 seen last.\n",
            if dropped == 1 { "row" } else { "rows" },
            if dropped == 1 { "was" } else { "were" },
        ));
    }
    if let Some(step) = next_step(rows, current) {
        output.push_str(&format!("\n{} {step}\n", style.status(Status::Next)));
    }
    output
}

/// A VM that isn't running has no log: it starts empty with the VM.
fn not_running(environment: &str) -> anyhow::Error {
    crate::error_report::with_next_step(
        anyhow::anyhow!("there's no refusal log while {environment} isn't running"),
        format!("cw --local start {environment}"),
    )
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or_default()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) async fn handle(args: PolicyLogArgs) -> anyhow::Result<()> {
    use codewire_local_vmm::supervisor_client::EgressRefusalsRead;

    let environment = crate::commands::environment::progress::terminal_text(&args.env);
    let mut client = crate::commands::native::native_client().await?;
    let log = match client.egress_refusals(&args.env).await {
        Ok(EgressRefusalsRead::Log(log)) => log,
        Ok(EgressRefusalsRead::NotRunning) => return Err(not_running(&environment)),
        Err(status) if status.code() == tonic::Code::Unimplemented => {
            anyhow::bail!("{}", status.message())
        }
        Err(status) => anyhow::bail!("read the refusal log: {}", status.message()),
    };
    let rows: Vec<Row> = log.refusals.iter().filter_map(Row::parse).collect();
    match args.output {
        OutputFormat::Json => println!("{}", json(&rows, log.dropped)?),
        OutputFormat::Text => {
            let caps = crate::output::Capabilities::from_process(crate::output::OutputMode::Text);
            // Only a terminal cuts the table to its width; a pipe gets it whole.
            let columns = if std::io::stdout().is_terminal() {
                usize::from(caps.columns)
            } else {
                usize::MAX
            };
            // Without the current revisions no step is offered, never a stale one.
            let current: HashMap<String, u32> = client
                .list_network_policies()
                .await
                .map(|policies| {
                    policies
                        .into_iter()
                        .map(|policy| (policy.name, policy.current_revision))
                        .collect()
                })
                .unwrap_or_default();
            print!(
                "{}",
                text(
                    &environment,
                    &rows,
                    log.dropped,
                    now_unix_ms(),
                    columns,
                    caps.stdout_style(),
                    &current,
                )
            );
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) async fn handle(_args: PolicyLogArgs) -> anyhow::Result<()> {
    anyhow::bail!("local network policies need a Linux or macOS host")
}

#[cfg(test)]
mod tests;
