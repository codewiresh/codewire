//! `StreamEnvironmentDaemonLogs` for a local VM: the supervisor's operation
//! lines, the guest daemon's recent log and the credential authority's lease
//! decisions for the environment (docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Diagnosing delivery in a local VM").

use codewire_daemon::client::SessionClientError;
use codewire_daemon::recent_log::RECENT_LOG_BYTES;
use codewire_local_credentials::{BrokerLeaseAuditDecision, BrokerLeaseAuditEvent};

use super::*;

/// The whole answer, which `public_client` also refuses to exceed. The three
/// parts' bounds below add up to it.
const MAXIMUM_DAEMON_LOG_BYTES: usize = 64 * 1024;
const MAXIMUM_OPERATION_BYTES: usize = 14 * 1024;
/// Room for a full guest log whose lines each gained their prefix.
const MAXIMUM_GUEST_BYTES: usize = 36 * 1024;
const MAXIMUM_LEASE_BYTES: usize = 12 * 1024;
const MAXIMUM_LEASE_EVENTS: usize = 64;
const _: () = assert!(
    MAXIMUM_OPERATION_BYTES + MAXIMUM_GUEST_BYTES + MAXIMUM_LEASE_BYTES + 2 * 1024
        <= MAXIMUM_DAEMON_LOG_BYTES
);

/// How long a guest or the authority may take to answer.
const PART_DEADLINE: Duration = Duration::from_secs(5);

const GUEST_LINE_PREFIX: &str = "guest: ";
const REPLACEMENT: char = '?';

impl SupervisorRpc {
    pub(super) async fn public_daemon_logs(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<Vec<u8>, connectrpc::ConnectError> {
        let (_, environment) = self.public_environment(org_id, environment_id).await?;
        let state = private_environment_state(environment.state)?;
        let environment_uuid = parse_coordinate(&environment.id, "environment_id")?;
        let operations = self
            .operation_reader
            .lock()
            .await
            .recent_environment_operations(environment_uuid)
            .map_err(|_| local_internal())?;

        let mut output = b"# operations\n".to_vec();
        output.extend(operation_lines(&operations)?);
        output.extend(b"# guest daemon\n");
        output.extend(match state {
            v1::EnvironmentState::Running => {
                guest_part(self.guest_daemon_log(org_id, environment_id).await)
            }
            _ => unavailable("guest daemon log", "the VM is not running"),
        });
        output.extend(b"# credential leases\n");
        output.extend(lease_part(self.lease_audit(environment_uuid).await));
        Ok(output)
    }

    async fn guest_daemon_log(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<Vec<u8>, GuestLogUnavailable> {
        let read = async {
            let client = self
                .public_daemon_probe_client(org_id, environment_id)
                .await
                .map_err(|_| GuestLogUnavailable::NoAnswer)?;
            client
                .read_daemon_log(RECENT_LOG_BYTES)
                .await
                .map_err(|error| match error {
                    SessionClientError::Status(status)
                        if status.code() == tonic::Code::Unimplemented =>
                    {
                        GuestLogUnavailable::OlderGuest
                    }
                    _ => GuestLogUnavailable::NoAnswer,
                })
        };
        tokio::time::timeout(PART_DEADLINE, read)
            .await
            .unwrap_or(Err(GuestLogUnavailable::NoAnswer))
    }

    /// Asks an authority that is already running, and never starts one.
    async fn lease_audit(
        &self,
        environment_id: Uuid,
    ) -> Result<codewire_local_credentials::EnvironmentLeaseAudit, LeasesUnavailable> {
        let read = async {
            let environment_id = EnvironmentId::parse(environment_id.to_string())
                .map_err(|_| LeasesUnavailable::NoAnswer)?;
            let config = self.supervisor.config.credential_authority_config();
            let mut authority = LocalCredentialControlClient::connect(&config)
                .await
                .map_err(|_| LeasesUnavailable::NotRunning)?;
            authority
                .environment_lease_audit(&environment_id, MAXIMUM_LEASE_EVENTS)
                .await
                .map_err(|_| LeasesUnavailable::NoAnswer)
        };
        tokio::time::timeout(PART_DEADLINE, read)
            .await
            .unwrap_or(Err(LeasesUnavailable::NoAnswer))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestLogUnavailable {
    /// The guest's daemon has no `ReadDaemonLog`.
    OlderGuest,
    /// No connection, no answer in time, a refusal or an answer over the
    /// bound.
    NoAnswer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeasesUnavailable {
    NotRunning,
    NoAnswer,
}

fn unavailable(what: &str, why: &str) -> Vec<u8> {
    format!("{what} unavailable: {why}\n").into_bytes()
}

fn operation_lines(operations: &[OperationRecord]) -> Result<Vec<u8>, connectrpc::ConnectError> {
    let mut output = Vec::new();
    for operation in operations {
        let stage = operation_stage(operation).map_err(local_status)?;
        let line = format!(
            "time_unix_ms={} operation={} kind={} phase={} checkpoint={} stage={} error={}\n",
            operation.updated_unix_ms,
            operation.operation_id,
            operation.kind.as_str(),
            operation.phase.as_str(),
            operation.checkpoint,
            stage.as_str_name(),
            operation.error_code.as_deref().unwrap_or("-"),
        );
        if output.len().saturating_add(line.len()) > MAXIMUM_OPERATION_BYTES {
            break;
        }
        output.extend_from_slice(line.as_bytes());
    }
    if output.is_empty() {
        output.extend(b"no operations recorded\n");
    }
    Ok(output)
}

fn guest_part(log: Result<Vec<u8>, GuestLogUnavailable>) -> Vec<u8> {
    match log {
        Ok(log) => {
            let lines = guest_lines(&log);
            if lines.is_empty() {
                b"no lines yet\n".to_vec()
            } else {
                lines
            }
        }
        Err(GuestLogUnavailable::OlderGuest) => unavailable(
            "guest daemon log",
            "this VM's guest is older than cw; restart the VM to get its daemon log",
        ),
        Err(GuestLogUnavailable::NoAnswer) => {
            unavailable("guest daemon log", "the guest daemon did not answer")
        }
    }
}

/// Guest-authored bytes made safe for the owner's terminal: every line is
/// prefixed so it cannot pass for `cw`'s own output, and nothing in it can
/// move the cursor, restyle or reorder text. The newest lines that fit
/// [`MAXIMUM_GUEST_BYTES`] are kept.
fn guest_lines(log: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(log);
    let mut lines: Vec<String> = Vec::new();
    let mut kept = 0_usize;
    for line in text.split('\n').rev().filter(|line| !line.is_empty()) {
        let mut rendered = String::with_capacity(GUEST_LINE_PREFIX.len() + line.len() + 1);
        rendered.push_str(GUEST_LINE_PREFIX);
        rendered.extend(line.chars().map(|character| {
            if terminal_unsafe(character) {
                REPLACEMENT
            } else {
                character
            }
        }));
        rendered.push('\n');
        if kept.saturating_add(rendered.len()) > MAXIMUM_GUEST_BYTES {
            break;
        }
        kept += rendered.len();
        lines.push(rendered);
    }
    lines.into_iter().rev().collect::<String>().into_bytes()
}

/// The C0 controls (the caller has already split on the line break), DEL and
/// the C1 controls, then the characters that reorder or break a line without
/// being controls: the bidirectional embeddings, overrides and isolates, and
/// the line and paragraph separators.
fn terminal_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}'
        )
}

fn lease_part(
    audit: Result<codewire_local_credentials::EnvironmentLeaseAudit, LeasesUnavailable>,
) -> Vec<u8> {
    let audit = match audit {
        Ok(audit) => audit,
        Err(LeasesUnavailable::NotRunning) => {
            return unavailable(
                "credential leases",
                "the credential authority is not running",
            );
        }
        Err(LeasesUnavailable::NoAnswer) => {
            return unavailable(
                "credential leases",
                "the credential authority did not answer",
            );
        }
    };
    let mut output = Vec::new();
    if audit.crowded {
        output.extend(
            b"older decisions may be missing: this credential authority is older than cw and lists every environment together\n",
        );
    }
    if audit.events.is_empty() {
        output.extend(
            b"no lease decisions recorded for this environment since the credential authority started\n",
        );
    }
    // The authority answers newest first.
    for event in audit.events.iter().rev() {
        let line = lease_line(event);
        if output.len().saturating_add(line.len()) > MAXIMUM_LEASE_BYTES {
            break;
        }
        output.extend(line.into_bytes());
    }
    output
}

/// Exactly the fields the specification lists, and no credential's id.
fn lease_line(event: &BrokerLeaseAuditEvent) -> String {
    format!(
        "time_unix_ms={} generation={} slot={} operation={} route={} decision={} credential={}\n",
        event.observed_at_unix_ms,
        event.environment_generation,
        event.capability_slot,
        event.operation,
        event.route,
        match event.decision {
            BrokerLeaseAuditDecision::Admitted => "admitted",
            BrokerLeaseAuditDecision::Denied => "denied",
            BrokerLeaseAuditDecision::Unavailable => "unavailable",
        },
        if event.credential_id.is_some() {
            "selected"
        } else {
            "none"
        },
    )
}

#[cfg(test)]
mod tests {
    use codewire_access::{
        AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId,
    };
    use codewire_local_credentials::EnvironmentLeaseAudit;

    use super::*;

    #[test]
    fn operation_lines_render_only_trusted_journal_fields() {
        let sentinel = "guest-output-and-token-sentinel";
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            environment_id: Some(Uuid::new_v4()),
            kind: OperationKind::Create,
            phase: OperationPhase::Completed,
            checkpoint: 7,
            payload: serde_json::json!({"name": sentinel}),
            result: Some(serde_json::json!({"message": sentinel})),
            error_code: None,
            created_unix_ms: 1_000,
            updated_unix_ms: 2_000,
        };

        let logs = String::from_utf8(operation_lines(&[operation]).unwrap()).unwrap();
        assert!(logs.contains("time_unix_ms=2000"));
        assert!(logs.contains("kind=create"));
        assert!(logs.contains("phase=completed"));
        assert!(logs.contains("stage=OPERATION_STAGE_COMPLETED"));
        assert!(!logs.contains(sentinel));
        assert!(logs.len() <= MAXIMUM_OPERATION_BYTES);
    }

    fn rendered(log: &[u8]) -> String {
        String::from_utf8(guest_lines(log)).unwrap()
    }

    #[test]
    fn every_guest_line_is_prefixed() {
        assert_eq!(
            rendered(b"first line\n\nsecond line\n"),
            "guest: first line\nguest: second line\n"
        );
        // A guest cannot start a line that reads as one of the other parts.
        assert_eq!(
            rendered(b"ok\n# credential leases\ndecision=admitted\n"),
            "guest: ok\nguest: # credential leases\nguest: decision=admitted\n"
        );
    }

    #[test]
    fn c0_controls_and_del_are_replaced() {
        for control in (0x00_u8..0x20).filter(|byte| *byte != b'\n').chain([0x7f]) {
            let line = [b"a".as_slice(), &[control], b"b\n"].concat();
            assert_eq!(rendered(&line), "guest: a?b\n", "byte {control:#04x}");
        }
        // An escape sequence loses its escape, and a carriage return cannot
        // overwrite the prefix.
        assert_eq!(
            rendered(b"\x1b[2J\x1b[31mred\rguest: forged\n"),
            "guest: ?[2J?[31mred?guest: forged\n"
        );
    }

    #[test]
    fn c1_controls_are_replaced() {
        for control in 0x80_u32..=0x9f {
            let control = char::from_u32(control).unwrap();
            assert_eq!(
                rendered(format!("a{control}b\n").as_bytes()),
                "guest: a?b\n",
                "character {control:?}"
            );
        }
    }

    #[test]
    fn bidirectional_and_line_separator_characters_are_replaced() {
        let reordering = ('\u{202A}'..='\u{202E}')
            .chain('\u{2066}'..='\u{2069}')
            .chain(['\u{2028}', '\u{2029}']);
        for character in reordering {
            assert_eq!(
                rendered(format!("a{character}b\n").as_bytes()),
                "guest: a?b\n",
                "character {character:?}"
            );
        }
    }

    #[test]
    fn bytes_that_are_not_utf8_are_replaced_and_text_is_kept() {
        assert_eq!(rendered(b"a\xff\xfeb\n"), "guest: a\u{fffd}\u{fffd}b\n");
        assert_eq!(
            rendered("caf\u{e9} \u{2713}\n".as_bytes()),
            "guest: caf\u{e9} \u{2713}\n"
        );
    }

    #[test]
    fn a_full_guest_log_of_short_lines_keeps_its_newest_within_the_bound() {
        let log: Vec<u8> = (0..RECENT_LOG_BYTES / 2)
            .flat_map(|index| [b'0' + u8::try_from(index % 10).unwrap(), b'\n'])
            .collect();
        let lines = guest_lines(&log);
        assert!(lines.len() <= MAXIMUM_GUEST_BYTES);
        assert!(lines.len() > MAXIMUM_GUEST_BYTES - 16);
        let last = b'0' + u8::try_from((RECENT_LOG_BYTES / 2 - 1) % 10).unwrap();
        assert!(lines.ends_with(&[b' ', last, b'\n']));
        assert!(lines.starts_with(GUEST_LINE_PREFIX.as_bytes()));
    }

    #[test]
    fn a_guest_that_cannot_be_read_says_why_in_one_line() {
        assert_eq!(
            guest_part(Err(GuestLogUnavailable::OlderGuest)),
            b"guest daemon log unavailable: this VM's guest is older than cw; restart the VM to get its daemon log\n"
        );
        assert_eq!(
            guest_part(Err(GuestLogUnavailable::NoAnswer)),
            b"guest daemon log unavailable: the guest daemon did not answer\n"
        );
        assert_eq!(guest_part(Ok(Vec::new())), b"no lines yet\n");
    }

    fn lease(sequence: u64, decision: BrokerLeaseAuditDecision) -> BrokerLeaseAuditEvent {
        BrokerLeaseAuditEvent {
            sequence,
            observed_at_unix_ms: 1_000 + sequence,
            environment_id: EnvironmentId::parse("environment").unwrap(),
            environment_generation: 4,
            request_id: Uuid::new_v4(),
            capability_slot: CapabilitySlot::parse("anthropic").unwrap(),
            operation: BrokerOperationId::parse("claude-login").unwrap(),
            route: BrokerRouteId::parse("claude-login").unwrap(),
            decision,
            credential_id: Some(CredentialId::parse("credential-id-sentinel").unwrap()),
            profile_id: Some(AccessProfileId::parse("profile-id-sentinel").unwrap()),
            profile_revision: Some(9),
            credential_revocation_generation: Some(2),
        }
    }

    #[test]
    fn lease_lines_are_oldest_first_and_hold_only_the_listed_fields() {
        let audit = EnvironmentLeaseAudit {
            // Newest first, as the authority answers.
            events: vec![
                lease(2, BrokerLeaseAuditDecision::Admitted),
                lease(1, BrokerLeaseAuditDecision::Denied),
            ],
            crowded: false,
        };
        let request_ids: Vec<String> = audit
            .events
            .iter()
            .map(|event| event.request_id.to_string())
            .collect();

        let output = String::from_utf8(lease_part(Ok(audit))).unwrap();
        assert_eq!(
            output,
            "time_unix_ms=1001 generation=4 slot=anthropic operation=claude-login route=claude-login decision=denied credential=selected\n\
             time_unix_ms=1002 generation=4 slot=anthropic operation=claude-login route=claude-login decision=admitted credential=selected\n"
        );
        assert!(!output.contains("sentinel"));
        assert!(request_ids.iter().all(|id| !output.contains(id)));
    }

    #[test]
    fn a_lease_without_a_credential_says_none() {
        let mut event = lease(1, BrokerLeaseAuditDecision::Unavailable);
        event.credential_id = None;
        assert!(lease_line(&event).ends_with("decision=unavailable credential=none\n"));
    }

    #[test]
    fn leases_that_cannot_be_read_or_are_empty_say_so() {
        assert_eq!(
            lease_part(Err(LeasesUnavailable::NotRunning)),
            b"credential leases unavailable: the credential authority is not running\n"
        );
        assert_eq!(
            lease_part(Err(LeasesUnavailable::NoAnswer)),
            b"credential leases unavailable: the credential authority did not answer\n"
        );
        assert_eq!(
            lease_part(Ok(EnvironmentLeaseAudit {
                events: Vec::new(),
                crowded: false,
            })),
            b"no lease decisions recorded for this environment since the credential authority started\n"
        );
        let crowded = String::from_utf8(lease_part(Ok(EnvironmentLeaseAudit {
            events: Vec::new(),
            crowded: true,
        })))
        .unwrap();
        assert!(crowded.starts_with("older decisions may be missing: "));
    }
}
