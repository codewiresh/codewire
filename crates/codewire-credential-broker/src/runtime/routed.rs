//! Codex's routed model origin on a front-door session (#3999).
//!
//! Codex sends its model call to the origin its account routing names: the
//! `workspace_backend_origin` of its account's entry in
//! `GET chatgpt.com/backend-api/wham/accounts/check`, or `chatgpt.com` for
//! `NO_CONSTRAINT`. The egress broker intercepts every name under a fixed
//! suffix ([`ROUTED_SUFFIXES`]) on 443, since it sees only a dial's name and
//! port. So a front-door session records the origin from the last reply it
//! served, and a request to a name under the suffix is served only when it
//! is that origin, on Codex's model path, dialled at the address the egress
//! broker admitted, which the broker checks again itself. Anything else
//! under the suffix is refused today and logged with its name. Under #4931's
//! rule a request without the placeholder will instead follow the network
//! policy, once the egress broker's signed decision exists; a placeholder
//! there stays refused on every policy.
//!
//! A session keeps two records, never mixed: one from replies served with
//! this environment's credential swapped in, found by the account the broker
//! itself sent, and one from replies forwarded with the environment's own
//! login, found by the account the environment named. A request with this
//! environment's placeholder is checked against the first, any other against
//! the second.
//!
//! The records belong to one session, so one environment and its selected
//! credential. They are held in memory only, each replaced by the next reply
//! of its kind, and gone with the session; nothing about them is persistent
//! or process-wide.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use bytes::Bytes;
use codewire_access::CredentialId;
use futures::Stream;

use super::{BrokerRequestError, BrokerResponseBody};
use crate::network::{ROUTED_SUFFIXES, admit_pinned, routed_host, routed_path};

/// The routing discovery Codex reads its model origin from.
pub(crate) const ACCOUNTS_CHECK_PATH: &str = "/backend-api/wham/accounts/check";
/// The most of one `accounts/check` reply read for its origin; a longer
/// reply records nothing.
const MAX_ROUTING_REPLY_BYTES: usize = 256 * 1024;
/// The most distinct refusals one session logs, each once.
const MAX_LOGGED_REFUSALS: usize = 32;

/// Whose credential a front-door request carries, which decides the record
/// it is checked against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Carried {
    /// This environment's placeholder: the broker swaps in the credential.
    Swapped,
    /// Any other credential, or none: forwarded as the environment sent it.
    Forwarded,
}

/// A front-door request's name under a routed suffix, and the address the
/// egress broker admitted for its dial, unchecked until the session's
/// [`FrontDoorSession::recorded_origin_admits`] checks it.
#[derive(Clone, Debug)]
pub(super) struct RoutedDial {
    pub(super) host: String,
    pub(super) destination: Option<IpAddr>,
}

/// One front-door session's routing state.
#[derive(Debug, Default)]
pub(crate) struct FrontDoorSession {
    /// The origin's host the last swapped `accounts/check` reply named for
    /// the credential's own account, if it was under a routed suffix.
    swapped: Mutex<Option<String>>,
    /// The same for the last forwarded reply, by the account the
    /// environment named.
    forwarded: Mutex<Option<String>>,
    /// The credential the swapped record was read for. A lease for another
    /// one clears that record (#3999).
    credential: Mutex<Option<CredentialId>>,
    /// What this session has logged, so each refusal is logged once.
    logged: Mutex<BTreeSet<(Refusal, String)>>,
    /// Refusals not logged because [`MAX_LOGGED_REFUSALS`] were already.
    dropped: AtomicU64,
}

impl Drop for FrontDoorSession {
    fn drop(&mut self) {
        let dropped = self.dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "front-door session ended with routed-origin refusals it did not log"
            );
        }
    }
}

/// Why a request to a name under a routed suffix was refused. Carries no
/// input; the name is logged beside it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Refusal {
    /// The origin a reply named is not under a routed suffix.
    OutsideList,
    /// This session's routing named no origin, or another one.
    NotRecorded,
    /// The routed origin serves only Codex's model path.
    Path,
    /// The front door named no admitted address, or one the broker would
    /// never dial.
    Destination,
}

impl Refusal {
    fn as_str(self) -> &'static str {
        match self {
            Self::OutsideList => "routed_origin_outside_list",
            Self::NotRecorded => "routed_origin_not_recorded",
            Self::Path => "routed_origin_path",
            Self::Destination => "routed_origin_destination",
        }
    }
}

impl FrontDoorSession {
    /// Whether a front-door request carrying `carried` for `host` and
    /// `path`, dialled at `destination`, may be served at a routed origin:
    /// `Ok(None)` when `host` is not under a routed suffix, so no routed
    /// origin applies; `Ok(Some(address))` with the address to dial when it
    /// is the origin this session recorded for that kind, on Codex's model
    /// path; `Err` otherwise, logged once with the name. An ordinary request
    /// takes this check before anything is leased or dialled. Every
    /// WebSocket upgrade is refused today; #4930 has the upgrade take this
    /// same check.
    pub(crate) fn recorded_origin_admits(
        &self,
        carried: Carried,
        host: &str,
        path: &str,
        destination: Option<IpAddr>,
    ) -> Result<Option<SocketAddr>, Refusal> {
        if !routed_host(host) {
            return Ok(None);
        }
        let recorded = self
            .record_for(carried)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let refusal = if recorded.as_deref() != Some(host) {
            Refusal::NotRecorded
        } else if !routed_path(path) {
            Refusal::Path
        } else {
            match destination.map(admit_pinned) {
                Some(Ok(address)) => return Ok(Some(address)),
                Some(Err(_)) | None => Refusal::Destination,
            }
        };
        self.log_once(refusal, host);
        Err(refusal)
    }

    /// Record the origin `reply`, an `accounts/check` body served on this
    /// session carrying `carried`, names for `account`: the credential's own
    /// account for a swapped reply, the one the environment named for a
    /// forwarded one. Replaced on every complete reply of that kind; cleared
    /// for `NO_CONSTRAINT`, `chatgpt.com` itself, an entry without one, or
    /// one that is not a valid HTTPS origin under a routed suffix.
    pub(crate) fn record(&self, carried: Carried, reply: &[u8], account: Option<&str>) {
        let origin = account.and_then(|account| workspace_backend_origin(reply, account));
        let recorded = match origin.as_deref() {
            None | Some("NO_CONSTRAINT") => None,
            Some(origin) => match routed_origin_host(origin) {
                Ok(host) => host,
                Err(named) => {
                    self.log_once(Refusal::OutsideList, &named);
                    None
                }
            },
        };
        *self
            .record_for(carried)
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = recorded;
    }

    fn record_for(&self, carried: Carried) -> &Mutex<Option<String>> {
        match carried {
            Carried::Swapped => &self.swapped,
            Carried::Forwarded => &self.forwarded,
        }
    }

    /// The origin this session would serve now for `carried`, for tests.
    #[cfg(test)]
    pub(crate) fn recorded(&self, carried: Carried) -> Option<String> {
        self.record_for(carried)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Note that a swapped request was leased `credential`. When it is not
    /// the credential the swapped record was read for, that record is
    /// cleared, so the new credential never goes to the old one's routed
    /// origin, and `true` is returned.
    pub(crate) fn credential_changed(&self, credential: &CredentialId) -> bool {
        let mut known = self
            .credential
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let changed = known.as_ref().is_some_and(|known| known != credential);
        if changed {
            *self.swapped.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
        *known = Some(credential.clone());
        changed
    }

    /// How many refusals went unlogged, for tests.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn log_once(&self, refusal: Refusal, name: &str) {
        let mut logged = self.logged.lock().unwrap_or_else(PoisonError::into_inner);
        if logged.len() >= MAX_LOGGED_REFUSALS && !logged.contains(&(refusal, name.to_owned())) {
            // A guest can use up the log with names of its choosing, so what
            // is not logged is counted, and said once.
            if self.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
                tracing::warn!(
                    "front-door session logged its last routed-origin refusal; later ones are only counted"
                );
            }
            return;
        }
        if logged.insert((refusal, name.to_owned())) {
            tracing::warn!(
                host = name,
                refusal = refusal.as_str(),
                "front-door request refused at a name under a routed suffix"
            );
        }
    }
}

/// `account`'s `workspace_backend_origin` in an `accounts/check` body. Only
/// the list form carries one; the older map form names no origin.
fn workspace_backend_origin(reply: &[u8], account: &str) -> Option<String> {
    let reply: serde_json::Value = serde_json::from_slice(reply).ok()?;
    reply
        .get("accounts")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("id").and_then(serde_json::Value::as_str) == Some(account))?
        .get("workspace_backend_origin")?
        .as_str()
        .map(str::to_owned)
}

/// The host a routed origin names, when it is one this broker serves: HTTPS,
/// no credentials, path, query or fragment, port 443 or none, and a host
/// exactly one label under a routed suffix. `Ok(None)` for a routed suffix itself,
/// which its exact route serves; `Err` with what to log for anything else.
fn routed_origin_host(origin: &str) -> Result<Option<String>, String> {
    let Ok(url) = url::Url::parse(origin) else {
        return Err("(not a URL)".to_owned());
    };
    let host = url.host_str().unwrap_or("(no host)").to_owned();
    let origin_form = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    if origin_form && ROUTED_SUFFIXES.contains(&host.as_str()) {
        return Ok(None);
    }
    if origin_form && routed_host(&host) {
        return Ok(Some(host));
    }
    Err(host)
}

/// `body`, as served carrying `carried`, recording the routing it names for
/// `account` on `session` once it has been read to its end, before its end
/// reaches the client.
pub(crate) fn recording(
    body: BrokerResponseBody,
    session: Arc<FrontDoorSession>,
    carried: Carried,
    account: Option<String>,
) -> BrokerResponseBody {
    Box::pin(Recording {
        body,
        session,
        carried,
        account,
        read: Some(Vec::new()),
    })
}

struct Recording {
    body: BrokerResponseBody,
    session: Arc<FrontDoorSession>,
    carried: Carried,
    account: Option<String>,
    /// What has been read so far; `None` once past the bound or failed.
    read: Option<Vec<u8>>,
}

impl Stream for Recording {
    type Item = Result<Bytes, BrokerRequestError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        match this.body.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(read) = this.read.as_mut() {
                    if read.len() + chunk.len() > MAX_ROUTING_REPLY_BYTES {
                        this.read = None;
                    } else {
                        read.extend_from_slice(&chunk);
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.read = None;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if let Some(read) = this.read.take() {
                    this.session
                        .record(this.carried, &read, this.account.as_deref());
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "account-work";
    const PUBLIC: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(162, 159, 140, 245));

    fn check(origin: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "accounts": [
                {"id": "account-other", "workspace_backend_origin": "https://other.chatgpt.com"},
                {"id": ACCOUNT, "workspace_backend_origin": origin,
                 "account_routing_override": "us", "structure": "workspace"},
            ],
            "account_ordering": [ACCOUNT],
        }))
        .unwrap()
    }

    #[test]
    fn only_a_valid_origin_under_the_list_is_recorded_for_the_account() {
        let session = FrontDoorSession::default();
        session.record(
            Carried::Swapped,
            &check("https://routed.chatgpt.com"),
            Some(ACCOUNT),
        );
        assert_eq!(
            session.recorded(Carried::Swapped).as_deref(),
            Some("routed.chatgpt.com")
        );
        // The URL parser lowercases the host, and then it is matched.
        session.record(
            Carried::Swapped,
            &check("https://Routed.ChatGPT.com"),
            Some(ACCOUNT),
        );
        assert_eq!(
            session.recorded(Carried::Swapped).as_deref(),
            Some("routed.chatgpt.com")
        );
        for cleared in [
            "NO_CONSTRAINT",
            "https://chatgpt.com",
            "https://a.b.chatgpt.com",
            "https://routed.chatgpt.com.",
            "https://routed.chatg\u{0440}t.com",
            "https://evil.example.com",
            "http://routed.chatgpt.com",
            "https://routed.chatgpt.com:8443",
            "https://routed.chatgpt.com/backend-api",
            "https://routed.chatgpt.com/?a=1",
            "https://user@routed.chatgpt.com",
            "https://xchatgpt.com",
            "https://10.0.0.1",
            "not a url",
        ] {
            session.record(
                Carried::Swapped,
                &check("https://routed.chatgpt.com"),
                Some(ACCOUNT),
            );
            session.record(Carried::Swapped, &check(cleared), Some(ACCOUNT));
            assert_eq!(session.recorded(Carried::Swapped), None, "{cleared}");
        }
        // Another account's entry, no account, or the map form record nothing.
        session.record(
            Carried::Swapped,
            &check("https://routed.chatgpt.com"),
            Some("account-none"),
        );
        assert_eq!(session.recorded(Carried::Swapped), None);
        session.record(Carried::Swapped, &check("https://routed.chatgpt.com"), None);
        assert_eq!(session.recorded(Carried::Swapped), None);
        let map = serde_json::to_vec(&serde_json::json!({
            "accounts": {ACCOUNT: {"account": {"account_id": ACCOUNT}}},
            "account_ordering": [ACCOUNT],
        }))
        .unwrap();
        session.record(Carried::Swapped, &map, Some(ACCOUNT));
        assert_eq!(session.recorded(Carried::Swapped), None);
    }

    #[test]
    fn a_name_under_the_suffix_is_admitted_only_as_the_recorded_origin() {
        let session = FrontDoorSession::default();
        let model = "/backend-api/codex/responses";
        // A bound host is not this check's: no routed origin applies.
        assert_eq!(
            session.recorded_origin_admits(Carried::Swapped, "chatgpt.com", model, None),
            Ok(None)
        );
        assert_eq!(
            session.recorded_origin_admits(
                Carried::Swapped,
                "routed.chatgpt.com",
                model,
                Some(PUBLIC)
            ),
            Err(Refusal::NotRecorded)
        );
        session.record(
            Carried::Swapped,
            &check("https://routed.chatgpt.com"),
            Some(ACCOUNT),
        );
        assert_eq!(
            session.recorded_origin_admits(
                Carried::Swapped,
                "routed.chatgpt.com",
                model,
                Some(PUBLIC)
            ),
            Ok(Some(SocketAddr::new(PUBLIC, 443)))
        );
        assert_eq!(
            session.recorded_origin_admits(
                Carried::Swapped,
                "other.chatgpt.com",
                model,
                Some(PUBLIC)
            ),
            Err(Refusal::NotRecorded)
        );
        assert_eq!(
            session.recorded_origin_admits(
                Carried::Swapped,
                "routed.chatgpt.com",
                "/backend-api/wham/usage",
                Some(PUBLIC)
            ),
            Err(Refusal::Path)
        );
        for destination in [
            None,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 254))),
            Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ] {
            assert_eq!(
                session.recorded_origin_admits(
                    Carried::Swapped,
                    "routed.chatgpt.com",
                    model,
                    destination
                ),
                Err(Refusal::Destination),
                "{destination:?}"
            );
        }
        // Another session never saw this routing.
        assert_eq!(
            FrontDoorSession::default().recorded_origin_admits(
                Carried::Swapped,
                "routed.chatgpt.com",
                model,
                Some(PUBLIC)
            ),
            Err(Refusal::NotRecorded)
        );
    }

    /// The two records never stand in for each other.
    #[test]
    fn a_swapped_and_a_forwarded_record_are_kept_apart() {
        let session = FrontDoorSession::default();
        let model = "/backend-api/codex/responses";
        session.record(
            Carried::Forwarded,
            &check("https://routed.chatgpt.com"),
            Some(ACCOUNT),
        );
        assert_eq!(session.recorded(Carried::Swapped), None);
        assert_eq!(
            session.recorded_origin_admits(
                Carried::Swapped,
                "routed.chatgpt.com",
                model,
                Some(PUBLIC)
            ),
            Err(Refusal::NotRecorded)
        );
        assert_eq!(
            session.recorded_origin_admits(
                Carried::Forwarded,
                "routed.chatgpt.com",
                model,
                Some(PUBLIC)
            ),
            Ok(Some(SocketAddr::new(PUBLIC, 443)))
        );
        session.record(
            Carried::Swapped,
            &check("https://swapped.chatgpt.com"),
            Some(ACCOUNT),
        );
        assert_eq!(
            session.recorded(Carried::Swapped).as_deref(),
            Some("swapped.chatgpt.com")
        );
        assert_eq!(
            session.recorded(Carried::Forwarded).as_deref(),
            Some("routed.chatgpt.com")
        );
        assert_eq!(
            session.recorded_origin_admits(
                Carried::Forwarded,
                "swapped.chatgpt.com",
                model,
                Some(PUBLIC)
            ),
            Err(Refusal::NotRecorded)
        );
    }

    /// A lease for another credential clears the swapped record, so the new
    /// credential never goes to the old one's origin; the forwarded record
    /// is the environment's own and stays.
    #[test]
    fn another_credential_clears_the_swapped_record() {
        let session = FrontDoorSession::default();
        let first = CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let second = CredentialId::parse("22222222-2222-4222-8222-222222222222").unwrap();
        assert!(!session.credential_changed(&first));
        session.record(
            Carried::Swapped,
            &check("https://routed.chatgpt.com"),
            Some(ACCOUNT),
        );
        session.record(
            Carried::Forwarded,
            &check("https://routed.chatgpt.com"),
            Some(ACCOUNT),
        );
        assert!(!session.credential_changed(&first));
        assert!(session.recorded(Carried::Swapped).is_some());
        assert!(session.credential_changed(&second));
        assert_eq!(session.recorded(Carried::Swapped), None);
        assert!(session.recorded(Carried::Forwarded).is_some());
    }

    /// Past the log's bound, refusals are counted instead of logged.
    #[test]
    fn refusals_past_the_log_bound_are_counted() {
        let session = FrontDoorSession::default();
        for index in 0..MAX_LOGGED_REFUSALS + 5 {
            let _ = session.recorded_origin_admits(
                Carried::Swapped,
                &format!("r{index}.chatgpt.com"),
                "/backend-api/codex/responses",
                Some(PUBLIC),
            );
        }
        assert_eq!(session.logged.lock().unwrap().len(), MAX_LOGGED_REFUSALS);
        assert_eq!(session.dropped(), 5);
        // A refusal already logged is neither logged again nor counted.
        let _ = session.recorded_origin_admits(
            Carried::Swapped,
            "r0.chatgpt.com",
            "/backend-api/codex/responses",
            Some(PUBLIC),
        );
        assert_eq!(session.dropped(), 5);
    }

    #[test]
    fn each_refusal_is_logged_once_per_session() {
        let session = FrontDoorSession::default();
        for _ in 0..3 {
            session.record(
                Carried::Swapped,
                &check("https://evil.example.com"),
                Some(ACCOUNT),
            );
            let _ = session.recorded_origin_admits(
                Carried::Swapped,
                "routed.chatgpt.com",
                "/backend-api/codex/responses",
                Some(PUBLIC),
            );
        }
        let logged = session.logged.lock().unwrap().clone();
        assert_eq!(
            logged,
            BTreeSet::from([
                (Refusal::OutsideList, "evil.example.com".to_owned()),
                (Refusal::NotRecorded, "routed.chatgpt.com".to_owned()),
            ])
        );
    }
}
