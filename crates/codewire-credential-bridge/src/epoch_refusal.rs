//! An epoch the broker refused to admit, for a named reason (#6406): a
//! Sandbox whose creator left its organization or was disabled. The relay
//! sends the refusal in place of Open, and the guest keeps it until the next
//! admitted epoch, for at most [`EPOCH_REFUSAL_LIFETIME`], each refused retry
//! renewing it. While it holds, a request without an epoch is answered with
//! it and a login is denied, so the daemon removes its delivered login.

use std::time::Duration;

use codewire_access::Refusal;

use crate::login::LoginFailure;
use crate::{BridgeFailure, BridgeState, PreparedBridgeConnection};

/// How long a refused admission is kept without a newer one.
pub(crate) const EPOCH_REFUSAL_LIFETIME: Duration = Duration::from_secs(60);

impl BridgeState {
    /// The broker's refusal of the last epoch, while it is fresh.
    fn epoch_refusal(&self) -> Option<Refusal> {
        self.refused
            .filter(|(_, at)| at.elapsed() < EPOCH_REFUSAL_LIFETIME)
            .map(|(refusal, _)| refusal)
    }

    /// A request's failure when no epoch is active.
    pub(crate) fn no_epoch_failure(&self) -> BridgeFailure {
        self.epoch_refusal()
            .map_or(BridgeFailure::Unavailable, BridgeFailure::Refused)
    }

    /// A login's failure when no epoch is active: a refused epoch is a
    /// denial, so the daemon removes the login it wrote.
    pub(crate) fn no_epoch_login_failure(&self) -> LoginFailure {
        if self.epoch_refusal().is_some() {
            LoginFailure::Denied
        } else {
            LoginFailure::Unavailable
        }
    }
}

impl PreparedBridgeConnection {
    /// Keep the broker's refusal of this connection's epoch in place of
    /// activating it. A refusal for an identity the bridge has since rotated
    /// away from is dropped.
    pub async fn refuse(self, refusal: Refusal) {
        if self.bridge.identity() != self.identity {
            return;
        }
        self.bridge.inner.lock().await.refused = Some((refusal, tokio::time::Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use tokio_stream::wrappers::ReceiverStream;
    use uuid::Uuid;

    use super::*;
    use crate::CredentialBridge;
    use codewire_daemon_proto::codewire::bridge::v1;

    fn bridge() -> CredentialBridge {
        CredentialBridge::new(Uuid::new_v4(), 7).unwrap()
    }

    async fn request(bridge: &CredentialBridge) -> Result<(), BridgeFailure> {
        bridge
            .submit(v1::CredentialBridgeRequest::default(), None)
            .await
            .map(|_| ())
    }

    /// A refused epoch answers with its refusal and denies a login, so the
    /// daemon removes the one it wrote, for 60 seconds; then, as before, an
    /// unadmitted bridge is unavailable (#6406).
    #[tokio::test(start_paused = true)]
    async fn a_refused_epoch_answers_with_its_refusal_until_it_lapses() {
        let bridge = bridge();
        let (prepared, _output) = bridge.prepare_connection().unwrap();
        prepared.refuse(Refusal::CredentialOwnerDeparted).await;
        assert!(matches!(
            request(&bridge).await,
            Err(BridgeFailure::Refused(Refusal::CredentialOwnerDeparted))
        ));
        assert_eq!(
            bridge.codex_login().await.unwrap_err(),
            LoginFailure::Denied
        );

        tokio::time::advance(EPOCH_REFUSAL_LIFETIME).await;
        assert!(matches!(
            request(&bridge).await,
            Err(BridgeFailure::Unavailable)
        ));
        assert_eq!(
            bridge.codex_login().await.unwrap_err(),
            LoginFailure::Unavailable
        );
    }

    /// Each refused retry renews it, and the next admitted epoch clears it.
    #[tokio::test(start_paused = true)]
    async fn a_retry_renews_the_refusal_and_an_admitted_epoch_clears_it() {
        let bridge = bridge();
        let (prepared, _output) = bridge.prepare_connection().unwrap();
        prepared.refuse(Refusal::CredentialOwnerDisabled).await;
        tokio::time::advance(EPOCH_REFUSAL_LIFETIME / 2).await;
        let (prepared, _output) = bridge.prepare_connection().unwrap();
        prepared.refuse(Refusal::CredentialOwnerDisabled).await;
        tokio::time::advance(EPOCH_REFUSAL_LIFETIME / 2).await;
        assert!(matches!(
            request(&bridge).await,
            Err(BridgeFailure::Refused(Refusal::CredentialOwnerDisabled))
        ));

        let (prepared, _output) = bridge.prepare_connection().unwrap();
        let (_input, receiver) = tokio::sync::mpsc::channel(1);
        let _connection = prepared
            .activate(ReceiverStream::new(receiver))
            .await
            .unwrap();
        assert!(bridge.inner.lock().await.refused.is_none());
    }
}
