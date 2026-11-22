//! The lease channel's answers as RPC statuses, both ways. A withheld
//! credential's reason crosses as metadata on the denial, so the broker
//! answers the same refusal a hosted Sandbox does (#5593). A rate-limited
//! refresh (#4975) carries the seconds left as `retry-after`.

use codewire_access::WithheldReason;
use tonic::Status;
use tonic::metadata::MetadataValue;

use super::BrokerLeaseChannelError;
use crate::LocalCredentialError;

const RETRY_AFTER: &str = "retry-after";

/// The seconds a rate-limited answer names. One without a readable value
/// waits the shortest bound.
fn retry_after(status: &Status) -> u64 {
    status
        .metadata()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(*crate::refresh_journal::RATE_LIMIT_WAIT_SECONDS.start())
}

/// The metadata key that names why the slot's credential is withheld; never
/// an id.
const WITHHELD_KEY: &str = "codewire-credential-withheld";

fn withheld_name(reason: WithheldReason) -> &'static str {
    match reason {
        WithheldReason::Revoked => "revoked",
        WithheldReason::Expired => "expired",
        WithheldReason::NeedsReconnect => "needs_reconnect",
    }
}

/// A denial that says why, so the broker can tell the agent.
fn withheld(reason: WithheldReason) -> Status {
    let mut status = Status::failed_precondition("credential broker lease was denied");
    status.metadata_mut().insert(
        WITHHELD_KEY,
        MetadataValue::from_static(withheld_name(reason)),
    );
    status
}

/// The reason a denial carries, if it names exactly one this broker knows:
/// a second value, or one that isn't plain ASCII, is no reason.
fn withheld_of(status: &Status) -> Option<WithheldReason> {
    let mut values = status.metadata().get_all(WITHHELD_KEY).iter();
    let name = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    [
        WithheldReason::Revoked,
        WithheldReason::Expired,
        WithheldReason::NeedsReconnect,
    ]
    .into_iter()
    .find(|reason| withheld_name(*reason) == name)
}

pub(super) fn map_client_status(status: Status) -> BrokerLeaseChannelError {
    match status.code() {
        tonic::Code::InvalidArgument => BrokerLeaseChannelError::InvalidRequest,
        tonic::Code::Aborted => BrokerLeaseChannelError::RefreshInProgress,
        tonic::Code::OutOfRange => BrokerLeaseChannelError::StaleRefresh,
        tonic::Code::ResourceExhausted => BrokerLeaseChannelError::RateLimited {
            retry_after_seconds: retry_after(&status),
        },
        tonic::Code::FailedPrecondition => match withheld_of(&status) {
            Some(reason) => BrokerLeaseChannelError::Withheld(reason),
            None => BrokerLeaseChannelError::Denied,
        },
        tonic::Code::PermissionDenied => BrokerLeaseChannelError::Denied,
        _ => BrokerLeaseChannelError::Unavailable,
    }
}

pub(super) fn map_server_error(error: LocalCredentialError) -> Status {
    match error {
        LocalCredentialError::CredentialWithheld(reason) => withheld(reason),
        LocalCredentialError::StaleCredentialRefresh => {
            Status::out_of_range("credential refresh generation changed")
        }
        LocalCredentialError::CredentialOperationLeaseDenied
        | LocalCredentialError::CredentialInactive
        | LocalCredentialError::CredentialUnavailable
        | LocalCredentialError::CredentialMaterialMissing
        | LocalCredentialError::CredentialNotFound
        | LocalCredentialError::EnvironmentBindingNotFound
        | LocalCredentialError::StaleEnvironmentBinding
        | LocalCredentialError::ProfileNotFound
        | LocalCredentialError::ProfileRevisionNotFound
        | LocalCredentialError::StaleProfileRevision
        | LocalCredentialError::StaleCredentialRevision
        | LocalCredentialError::Access(_) => {
            Status::failed_precondition("credential broker lease was denied")
        }
        LocalCredentialError::CredentialRefreshInProgress => {
            Status::aborted("credential refresh is already in progress")
        }
        LocalCredentialError::CredentialRefreshRateLimited {
            retry_after_seconds,
        } => {
            let mut status =
                Status::resource_exhausted("credential refresh is rate-limited by the provider");
            if let Ok(value) = retry_after_seconds.to_string().parse() {
                status.metadata_mut().insert(RETRY_AFTER, value);
            }
            status
        }
        _ => Status::unavailable("credential broker lease authority is unavailable"),
    }
}

#[cfg(test)]
mod tests;
