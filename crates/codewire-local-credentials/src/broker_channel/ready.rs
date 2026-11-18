//! The launch handshake's Ready: what a broker child reports once it serves.

use std::collections::BTreeSet;

use codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeReady;
use codewire_protected_store::ProtectedStore;
use tonic::Status;

use super::{
    BROKER_LEASE_PROTOCOL_VERSION, BrokerLeaseChannelError, LocalCredentialBrokerLeaseClient,
    delegation, map_client_status, v1,
};

/// A broker selects a handful of provider hosts; more is not a broker's
/// report.
const MAX_UNRESOLVED_HOSTS: usize = 16;

/// What a ready broker child reported to its authority.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BrokerReady {
    /// Provider hosts the child found no address for at its start, and so
    /// does not serve (#5286). Empty when it resolved every one.
    pub unresolved_hosts: BTreeSet<String>,
}

impl BrokerReady {
    /// Admits a report's unresolved hosts. The authority hands them to the
    /// next child as arguments and writes them to its log, so each must be a
    /// plain DNS name.
    pub(super) fn admit(unresolved_hosts: Vec<String>) -> Result<Self, Status> {
        let reported = unresolved_hosts.len();
        let unresolved_hosts: BTreeSet<String> = unresolved_hosts.into_iter().collect();
        if reported > MAX_UNRESOLVED_HOSTS
            || unresolved_hosts.len() != reported
            || !unresolved_hosts.iter().all(|host| plain_dns_name(host))
        {
            return Err(Status::invalid_argument(
                "credential broker Ready names an invalid provider host",
            ));
        }
        Ok(Self { unresolved_hosts })
    }
}

fn plain_dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

impl<S> LocalCredentialBrokerLeaseClient<S>
where
    S: ProtectedStore + Clone + 'static,
{
    /// Complete the authority-owned launch handshake only after the broker has
    /// authenticated and opened the matching guest-daemon bridge.
    /// `unresolved_hosts` are the provider hosts it found no address for and
    /// does not serve.
    pub async fn report_ready(
        &mut self,
        ready: CredentialBridgeReady,
        unresolved_hosts: Vec<String>,
    ) -> Result<(), BrokerLeaseChannelError> {
        if !delegation::ready_matches(&self.environment_id, self.environment_generation, &ready) {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        self.inner
            .report_broker_ready(v1::BrokerReadyRequest {
                protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
                guest_ready: Some(ready),
                unresolved_provider_hosts: unresolved_hosts,
            })
            .await
            .map_err(map_client_status)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report's hosts are admitted only as a small set of plain DNS
    /// names: nothing that could be read as an argument or break a log line.
    #[test]
    fn a_ready_report_admits_only_a_few_distinct_plain_dns_names() {
        let hosts = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(
            BrokerReady::admit(Vec::new()).unwrap(),
            BrokerReady::default()
        );
        assert_eq!(
            BrokerReady::admit(hosts(&["platform.claude.com", "api.anthropic.com"]))
                .unwrap()
                .unresolved_hosts
                .into_iter()
                .collect::<Vec<_>>(),
            ["api.anthropic.com", "platform.claude.com"]
        );
        for refused in [
            &["api.anthropic.com", "api.anthropic.com"][..],
            &["--start-whatever-resolves"],
            &["api.anthropic.com unresolved=none"],
            &["API.anthropic.com"],
            &["api..anthropic.com"],
            &[""],
        ] {
            assert_eq!(
                BrokerReady::admit(hosts(refused)).unwrap_err().code(),
                tonic::Code::InvalidArgument,
                "{refused:?}"
            );
        }
        let many: Vec<String> = (0..=MAX_UNRESOLVED_HOSTS)
            .map(|index| format!("host{index}.example"))
            .collect();
        assert!(BrokerReady::admit(many).is_err());
    }
}
