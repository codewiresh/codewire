use super::*;

/// A withheld slot's reason crosses the lease channel as itself, and only as
/// a name; a denial without one stays a plain denial (#5593).
#[test]
fn a_withheld_reason_crosses_the_lease_channel() {
    for reason in [
        WithheldReason::Revoked,
        WithheldReason::Expired,
        WithheldReason::NeedsReconnect,
    ] {
        let status = map_server_error(LocalCredentialError::CredentialWithheld(reason));
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "credential broker lease was denied");
        assert_eq!(
            status.metadata().get(WITHHELD_KEY).unwrap(),
            withheld_name(reason)
        );
        assert_eq!(
            map_client_status(status),
            BrokerLeaseChannelError::Withheld(reason)
        );
    }
    for denied in [
        map_server_error(LocalCredentialError::CredentialOperationLeaseDenied),
        map_server_error(LocalCredentialError::CredentialInactive),
        Status::permission_denied("credential broker lease was denied"),
    ] {
        assert_eq!(map_client_status(denied), BrokerLeaseChannelError::Denied);
    }
    let mut unknown = Status::failed_precondition("credential broker lease was denied");
    unknown
        .metadata_mut()
        .insert(WITHHELD_KEY, MetadataValue::from_static("later_reason"));
    assert_eq!(map_client_status(unknown), BrokerLeaseChannelError::Denied);
    // Two reasons are none, even when the first is known.
    let mut twice = withheld(WithheldReason::Revoked);
    twice
        .metadata_mut()
        .append(WITHHELD_KEY, MetadataValue::from_static("expired"));
    assert_eq!(map_client_status(twice), BrokerLeaseChannelError::Denied);
    // A value that isn't plain ASCII is no reason.
    let mut opaque = Status::failed_precondition("credential broker lease was denied");
    opaque.metadata_mut().insert(
        WITHHELD_KEY,
        MetadataValue::try_from(&b"revoked\xff"[..]).unwrap(),
    );
    assert_eq!(map_client_status(opaque), BrokerLeaseChannelError::Denied);
}
