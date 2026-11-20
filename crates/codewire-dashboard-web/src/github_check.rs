//! The credentials page's live GitHub permission check, kept to one call per
//! person in a short window (#5206).

use std::collections::HashMap;
use std::time::Duration;

use axum::http::HeaderValue;
use tracing::Instrument as _;

use codewire_proto::codewire::v1::{
    GithubRepositoryServiceClient, ListGithubPendingPermissionsRequest,
};
use connectrpc::client::ClientConfig;

use crate::credentials_connect::{
    GITHUB_PENDING_TIMEOUT, GithubPendingPermissions, MAX_GITHUB_PENDING_RESPONSE_BYTES,
};
use crate::state::AppState;
use crate::transport::BrowserTransport;

/// One live check per person in this time (#5206). Reloads, or a script that
/// loops, ask GitHub no more often, and a person gets their own last answer
/// in between. The GitHub App's rate limit is shared by everyone. An entry
/// stays until that person's next check or until the table is full.
const GITHUB_CHECK_WINDOW: Duration = Duration::from_secs(45);
/// People whose last check is kept. Past it, a person with no entry is not
/// checked at all until an entry expires: the bound is on memory and on calls.
const GITHUB_CHECK_PEOPLE: usize = 4096;

/// What the live GitHub check last found for each person, and when it was
/// asked. Held in this process's memory only, never shared between people,
/// and never written anywhere.
#[derive(Default)]
pub(crate) struct GithubChecks(std::sync::Mutex<HashMap<String, GithubCheck>>);

struct GithubCheck {
    asked_at: std::time::Instant,
    found: Vec<GithubPendingPermissions>,
}

/// What a person's request does about the check.
#[derive(Debug, PartialEq, Eq)]
enum CheckStep {
    /// The window is open: use this person's last answer.
    Reuse(Vec<GithubPendingPermissions>),
    /// Ask GitHub now; the window starts.
    Ask,
    /// Too many people are held to start another window: say nothing.
    Skip,
}

impl GithubChecks {
    fn begin(&self, person: &str, now: std::time::Instant) -> CheckStep {
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(check) = held.get_mut(person) {
            if now.saturating_duration_since(check.asked_at) < GITHUB_CHECK_WINDOW {
                return CheckStep::Reuse(check.found.clone());
            }
            // The last answer is older than the window: nothing is shown
            // from it while the new check runs.
            check.asked_at = now;
            check.found = Vec::new();
            return CheckStep::Ask;
        }
        if held.len() >= GITHUB_CHECK_PEOPLE {
            held.retain(|_, check| {
                now.saturating_duration_since(check.asked_at) < GITHUB_CHECK_WINDOW
            });
            if held.len() >= GITHUB_CHECK_PEOPLE {
                return CheckStep::Skip;
            }
        }
        held.insert(
            person.to_owned(),
            GithubCheck {
                asked_at: now,
                found: Vec::new(),
            },
        );
        CheckStep::Ask
    }

    /// A connection that has just been made or remade changes what the check
    /// would find, so the person's window ends and the next page asks again.
    /// Only a completed GitHub connect calls it; it is not reachable from a
    /// page load or a query string.
    pub(crate) fn forget(&self, person: &str) {
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.remove(person);
    }

    fn finish(&self, person: &str, found: Vec<GithubPendingPermissions>) {
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(check) = held.get_mut(person) {
            check.found = found;
        }
    }
}

/// The installations still short of the permissions Codewire needs, for one
/// person, asking GitHub at most once per [`GITHUB_CHECK_WINDOW`]. A failed or
/// slow check is an empty answer, and the window still counts, so a failing
/// GitHub is not asked again sooner.
pub(crate) async fn github_pending_checked(
    state: &AppState,
    person: &str,
    cookie: HeaderValue,
) -> Vec<GithubPendingPermissions> {
    match state.github_checks.begin(person, std::time::Instant::now()) {
        CheckStep::Reuse(found) => found,
        CheckStep::Skip => Vec::new(),
        CheckStep::Ask => {
            let found = github_pending_permissions(state, cookie).await;
            state.github_checks.finish(person, found.clone());
            found
        }
    }
}

/// The installations of the signed-in person's GitHub App connection that
/// have not yet granted what Codewire needs, checked live by the credential
/// service with that person's own connection and authority (#2712). Advisory:
/// an error, or no answer within two seconds, is an empty list, so the page
/// never fails or waits long because of GitHub. The span names how the call
/// ended (`ok`, the Connect code, or `timed_out` when this bound fires before
/// the client's own, which has the same length) and never a message.
async fn github_pending_permissions(
    state: &AppState,
    cookie: HeaderValue,
) -> Vec<GithubPendingPermissions> {
    let client = GithubRepositoryServiceClient::new(
        BrowserTransport {
            http: state.credential_http.clone(),
            cookie: Some(cookie),
            origin: Some(
                HeaderValue::from_str(&state.public_origin)
                    .expect("validated dashboard public origin is a valid header value"),
            ),
        },
        ClientConfig::new(state.credential_origin.clone())
            .with_default_timeout(GITHUB_PENDING_TIMEOUT)
            .with_default_max_message_size(MAX_GITHUB_PENDING_RESPONSE_BYTES),
    );
    let span = tracing::info_span!(
        "github_pending_permissions",
        outcome = tracing::field::Empty
    );
    let call = tokio::time::timeout(
        GITHUB_PENDING_TIMEOUT,
        client.list_github_pending_permissions(ListGithubPendingPermissionsRequest::default()),
    )
    .instrument(span.clone())
    .await;
    let (outcome, found) = match call {
        Ok(Ok(response)) => (
            "ok",
            GithubPendingPermissions::from_wire(&response.into_owned().pending_permissions),
        ),
        Ok(Err(error)) => (error.code.as_str(), Vec::new()),
        Err(_) => ("timed_out", Vec::new()),
    };
    span.record("outcome", outcome);
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials_connect::GithubAccountKind;

    fn short(account: &str) -> Vec<GithubPendingPermissions> {
        vec![GithubPendingPermissions::new(account, 41, GithubAccountKind::User).unwrap()]
    }

    #[test]
    fn a_person_is_asked_about_once_per_window_and_gets_their_own_last_answer() {
        use std::time::Instant;
        let checks = GithubChecks::default();
        let start = Instant::now();
        // The first request asks, and a concurrent one reuses the empty answer.
        assert_eq!(checks.begin("alice", start), CheckStep::Ask);
        assert_eq!(
            checks.begin("alice", start + Duration::from_secs(1)),
            CheckStep::Reuse(Vec::new())
        );
        checks.finish("alice", short("octo-alice"));
        // Reloads inside the window do not ask again.
        for seconds in [2, 10, 44] {
            assert_eq!(
                checks.begin("alice", start + Duration::from_secs(seconds)),
                CheckStep::Reuse(short("octo-alice")),
                "{seconds} s"
            );
        }
        // Another person never sees alice's answer, and asks for themselves.
        assert_eq!(
            checks.begin("bob", start + Duration::from_secs(3)),
            CheckStep::Ask
        );
        assert_eq!(
            checks.begin("bob", start + Duration::from_secs(4)),
            CheckStep::Reuse(Vec::new())
        );
        // After the window alice asks again.
        assert_eq!(
            checks.begin("alice", start + GITHUB_CHECK_WINDOW),
            CheckStep::Ask
        );
        // The old answer is not shown while the new check runs.
        assert_eq!(
            checks.begin(
                "alice",
                start + GITHUB_CHECK_WINDOW + Duration::from_secs(1)
            ),
            CheckStep::Reuse(Vec::new())
        );
        // A completed GitHub connect ends the window early, for that person only.
        checks.finish("alice", short("octo-alice"));
        checks.forget("alice");
        assert_eq!(
            checks.begin(
                "alice",
                start + GITHUB_CHECK_WINDOW + Duration::from_secs(1)
            ),
            CheckStep::Ask
        );
        assert_eq!(
            checks.begin("bob", start + GITHUB_CHECK_WINDOW + Duration::from_secs(10)),
            CheckStep::Ask
        );
    }

    #[test]
    fn a_full_table_asks_nobody_new_until_an_entry_expires() {
        use std::time::Instant;
        let checks = GithubChecks::default();
        let start = Instant::now();
        for person in 0..GITHUB_CHECK_PEOPLE {
            assert_eq!(
                checks.begin(&format!("person-{person}"), start),
                CheckStep::Ask
            );
        }
        let inside = start + Duration::from_secs(1);
        assert_eq!(checks.begin("one-more", inside), CheckStep::Skip);
        // The same people are still answered, not skipped.
        assert_eq!(
            checks.begin("person-0", inside),
            CheckStep::Reuse(Vec::new())
        );
        // Once the entries expire, a new person is asked and the table shrinks.
        assert_eq!(
            checks.begin("one-more", start + GITHUB_CHECK_WINDOW),
            CheckStep::Ask
        );
    }
}
