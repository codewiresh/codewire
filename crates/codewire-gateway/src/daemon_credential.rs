//! The credential the gateway presents to its workspace daemon (Program #2238
//! B2, design §9).
//!
//! A legacy workspace's credential is the rendered environment-wide daemon
//! token and never changes. An identity-free workspace's credential is bound to
//! one Pod: the gateway fetches it through its own authenticated binding
//! (`IssueGatewayDaemonCredential`) and keeps it here. Every daemon RPC reads
//! the current value, so after a refresh the next call authenticates to the
//! replacement Pod behind the same daemon Service. The value never appears in
//! `Debug` output or logs.
//!
//! An issued credential is derived from the session secret and the bound Pod
//! UID. A bound daemon never re-binds, so rotating the session secret takes
//! effect for a workspace only when its Pod is restarted: until then the
//! gateway keeps fetching a credential the running daemon refuses, and the
//! refresher backs off (`codewire_gateway_daemon_credential_refreshes_total`
//! counts it as `changed`, then `unchanged`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use codewire_gateway_proto::DaemonAuthToken;
use tokio::sync::Notify;

#[derive(Clone)]
pub struct DaemonCredential {
    inner: Arc<Inner>,
}

struct Inner {
    current: RwLock<Current>,
    /// Only an issued credential can be refreshed; a rendered token is fixed.
    refreshable: bool,
    refresh: Notify,
    /// Set by an accepted daemon call since the refresher last looked.
    authenticated: AtomicBool,
}

#[derive(Clone, PartialEq, Eq)]
struct Current {
    token: DaemonAuthToken,
    workspace_pod_uid: Option<String>,
}

impl std::fmt::Debug for DaemonCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let current = self.read();
        formatter
            .debug_struct("DaemonCredential")
            .field("token", &current.token)
            .field("workspace_pod_uid", &current.workspace_pod_uid)
            .field("refreshable", &self.inner.refreshable)
            .finish()
    }
}

impl DaemonCredential {
    /// The rendered environment-wide token of a legacy workspace.
    pub fn rendered(token: DaemonAuthToken) -> Self {
        Self::new(token, None, false)
    }

    /// A credential issued for the environment's currently bound Pod.
    pub fn issued(token: DaemonAuthToken, workspace_pod_uid: String) -> Self {
        Self::new(token, Some(workspace_pod_uid), true)
    }

    fn new(token: DaemonAuthToken, workspace_pod_uid: Option<String>, refreshable: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                current: RwLock::new(Current {
                    token,
                    workspace_pod_uid,
                }),
                refreshable,
                refresh: Notify::new(),
                authenticated: AtomicBool::new(false),
            }),
        }
    }

    fn read(&self) -> Current {
        self.inner
            .current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The credential for the next daemon call.
    pub fn token(&self) -> DaemonAuthToken {
        self.read().token
    }

    /// The bound Pod this credential was issued for, when issued.
    pub fn workspace_pod_uid(&self) -> Option<String> {
        self.read().workspace_pod_uid
    }

    pub fn refreshable(&self) -> bool {
        self.inner.refreshable
    }

    /// The daemon refused this credential. An issued credential is fetched
    /// again; a rendered token cannot change, so this is a no-op for it.
    pub fn report_unauthenticated(&self) {
        if self.inner.refreshable {
            self.inner.refresh.notify_one();
        }
    }

    /// The daemon accepted a call with this credential. It resets the
    /// refresher's backoff, so the next refusal is followed at once.
    pub fn report_authenticated(&self) {
        if self.inner.refreshable && !self.inner.authenticated.load(Ordering::Relaxed) {
            self.inner.authenticated.store(true, Ordering::Release);
        }
    }

    /// Whether a daemon call was accepted since the last look, clearing it.
    pub(crate) fn take_authenticated(&self) -> bool {
        self.inner.authenticated.swap(false, Ordering::AcqRel)
    }

    /// Wait for the next refusal report.
    pub(crate) async fn refresh_requested(&self) {
        self.inner.refresh.notified().await;
    }

    /// Install a freshly issued credential. Returns whether it changed: a new
    /// workspace Pod, or a rotated derivation for the same Pod.
    pub(crate) fn replace(&self, token: DaemonAuthToken, workspace_pod_uid: String) -> bool {
        if !self.inner.refreshable {
            return false;
        }
        let next = Current {
            token,
            workspace_pod_uid: Some(workspace_pod_uid),
        };
        let mut current = self
            .inner
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *current == next {
            return false;
        }
        *current = next;
        true
    }
}

impl From<DaemonAuthToken> for DaemonCredential {
    fn from(token: DaemonAuthToken) -> Self {
        Self::rendered(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
    const REPLACEMENT_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";

    fn token(value: &str) -> DaemonAuthToken {
        DaemonAuthToken::new(value).unwrap()
    }

    #[tokio::test]
    async fn an_issued_credential_follows_a_replaced_pod() {
        let credential = DaemonCredential::issued(token("synthetic-first-credential"), POD.into());
        let shared = credential.clone();
        assert!(credential.refreshable());
        assert!(!credential.replace(token("synthetic-first-credential"), POD.into()));
        assert!(credential.replace(
            token("synthetic-replacement-credential"),
            REPLACEMENT_POD.into()
        ));
        // Every clone reads the replacement for its next call.
        assert_eq!(
            shared.token().expose_secret(),
            "synthetic-replacement-credential"
        );
        assert_eq!(shared.workspace_pod_uid().as_deref(), Some(REPLACEMENT_POD));

        // A refusal report wakes the refresher, even when made first.
        shared.report_unauthenticated();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            credential.refresh_requested(),
        )
        .await
        .expect("refresh requested");
    }

    #[tokio::test]
    async fn a_rendered_token_never_changes_or_requests_a_refresh() {
        let credential = DaemonCredential::rendered(token("synthetic-rendered-token"));
        assert!(!credential.refreshable());
        assert_eq!(credential.workspace_pod_uid(), None);
        credential.report_unauthenticated();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                credential.refresh_requested()
            )
            .await
            .is_err()
        );
        assert!(!credential.replace(token("synthetic-other-token"), POD.into()));
        assert_eq!(
            credential.token().expose_secret(),
            "synthetic-rendered-token"
        );
    }

    #[test]
    fn an_accepted_call_is_reported_once_and_only_for_an_issued_credential() {
        let issued = DaemonCredential::issued(token("synthetic-issued-credential"), POD.into());
        assert!(!issued.take_authenticated());
        issued.report_authenticated();
        issued.clone().report_authenticated();
        assert!(issued.take_authenticated());
        assert!(!issued.take_authenticated());

        let rendered = DaemonCredential::rendered(token("synthetic-rendered-token"));
        rendered.report_authenticated();
        assert!(!rendered.take_authenticated());
    }

    #[test]
    fn debug_output_redacts_the_credential() {
        let marker = "synthetic-credential-debug-marker";
        let debug = format!("{:?}", DaemonCredential::issued(token(marker), POD.into()));
        assert!(!debug.contains(marker), "{debug}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains(POD));
    }
}
