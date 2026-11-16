//! The refresh grant counter: each refresh token the service recognises,
//! by outcome and client (`docs/dev/OIDC-PROVIDER-THREAT-MODEL.md`,
//! "Refresh grant counter"). It measures how often clients replay a rotated
//! token before reuse revocation is turned on (#4786).

use codewire_server_core::metrics::{IntCounterVec, counter_vec};
use std::sync::OnceLock;

static REFRESH_GRANTS: OnceLock<IntCounterVec> = OnceLock::new();

fn refresh_grants() -> &'static IntCounterVec {
    REFRESH_GRANTS.get_or_init(|| {
        counter_vec(
            "codewire_idp_refresh_grants_total",
            "Refresh tokens the IdP recognised, by outcome (rotated, replayed, revoked) \
             and by the client they were issued to.",
            &["outcome", "client"],
        )
    })
}

/// What became of one recognised refresh token. Exactly one per grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    /// A live token was consumed and replaced.
    Rotated,
    /// A rotated token presented again, refused, with nothing revoked.
    Replayed,
    /// A rotated token presented again, refused, and the user's tokens for
    /// its client revoked.
    Revoked,
}

impl RefreshOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Rotated => "rotated",
            Self::Replayed => "replayed",
            Self::Revoked => "revoked",
        }
    }
}

/// The `client` label: one of the first-party clients `provisioning`
/// registers, or `other`, so no registration adds a series.
fn client_label(client_id: &str) -> &'static str {
    match client_id {
        "codewire-cli" => "codewire-cli",
        "codewire-desktop" => "codewire-desktop",
        "codewire-ios" => "codewire-ios",
        _ => "other",
    }
}

/// Counts one refresh token, issued to `client_id`, under `outcome`.
pub(crate) fn refresh_grant(outcome: RefreshOutcome, client_id: &str) {
    refresh_grants()
        .with_label_values(&[outcome.label(), client_label(client_id)])
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTCOMES: [RefreshOutcome; 3] = [
        RefreshOutcome::Rotated,
        RefreshOutcome::Replayed,
        RefreshOutcome::Revoked,
    ];
    const CLIENTS: [&str; 4] = ["codewire-cli", "codewire-desktop", "codewire-ios", "other"];

    #[test]
    fn only_the_first_party_clients_have_their_own_label() {
        for client in ["codewire-cli", "codewire-desktop", "codewire-ios"] {
            assert_eq!(client_label(client), client);
        }
        for chosen in [
            "",
            "other",
            "codewire-cli ",
            "CODEWIRE-DESKTOP",
            "codewire-ios\"}",
            "a-client-registered-later",
            &"x".repeat(4096),
        ] {
            assert_eq!(client_label(chosen), "other", "{chosen:?}");
        }
    }

    // The only test in this binary that counts refresh grants, so every
    // series but the one it names must stay where it was.
    #[test]
    fn a_grant_counts_once_under_its_outcome_and_client() {
        let snapshot = || {
            OUTCOMES.map(|outcome| {
                CLIENTS.map(|client| {
                    refresh_grants()
                        .with_label_values(&[outcome.label(), client])
                        .get()
                })
            })
        };
        let cases = [
            (RefreshOutcome::Rotated, "codewire-cli", 0, 0),
            (RefreshOutcome::Replayed, "codewire-desktop", 1, 1),
            (RefreshOutcome::Revoked, "codewire-ios", 2, 2),
            (RefreshOutcome::Revoked, "a-client-registered-later", 2, 3),
        ];
        for (outcome, client_id, row, column) in cases {
            let mut expected = snapshot();
            expected[row][column] += 1;
            refresh_grant(outcome, client_id);
            assert_eq!(snapshot(), expected, "{outcome:?} for {client_id}");
        }
    }
}
