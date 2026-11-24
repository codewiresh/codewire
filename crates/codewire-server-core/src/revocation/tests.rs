//! The fence's rules without a database (#3586; AUTH-POLICY "Account access
//! revocation").

use super::*;

fn snapshot(text: &str) -> Snapshot {
    Snapshot::parse(text).expect("a well-formed snapshot")
}

#[test]
fn a_snapshot_parses_its_text_form_and_nothing_else() {
    assert_eq!(
        snapshot("10:15:11,13"),
        Snapshot {
            xmin: 10,
            xmax: 15,
            in_progress: HashSet::from([11, 13]),
        }
    );
    assert!(snapshot("10:10:").in_progress.is_empty());
    for malformed in [
        "",
        "10",
        "10:15",
        "10:15:x",
        "10:15:11,",
        "a:15:",
        "10:b:",
        "15:10:",
        "10:15:11:12",
        "-1:15:",
    ] {
        assert_eq!(Snapshot::parse(malformed), None, "{malformed:?}");
    }
}

#[test]
fn a_snapshot_sees_what_committed_before_it() {
    let taken = snapshot("10:15:11,13");
    assert!(taken.sees(9));
    assert!(taken.sees(10) && taken.sees(12) && taken.sees(14));
    assert!(!taken.sees(11) && !taken.sees(13));
    assert!(!taken.sees(15) && !taken.sees(16));
}

fn session(user: &str, session: &str) -> Admitted {
    Admitted::session(user, session)
}

fn row(key: Authority, revocation: Revocation, xact: u64) -> LogEntry {
    LogEntry {
        key,
        revocation,
        xact,
    }
}

fn revoked_now(watch: &Watch) -> Option<Revocation> {
    *watch.revoked.borrow()
}

#[test]
fn a_row_ends_only_the_streams_it_names_that_did_not_already_see_it() {
    let fence = Fence::new();
    let first = fence.register(&session("u1", "s1"), snapshot("100:100:"));
    let second = fence.register(&session("u1", "s2"), snapshot("100:100:"));
    let stranger = fence.register(&session("u2", "s3"), snapshot("100:100:"));

    // Signing out s1 ends only s1's stream.
    fence.dispatch(&[row(
        Authority::Session("s1".into()),
        Revocation::Session,
        100,
    )]);
    assert_eq!(revoked_now(&first), Some(Revocation::Session));
    assert_eq!(revoked_now(&second), None);

    // A row the stream's snapshot already saw never ends it.
    fence.dispatch(&[row(Authority::User("u1".into()), Revocation::User, 99)]);
    assert_eq!(revoked_now(&second), None);

    // Disabling u1 ends the rest of u1's streams; the first loss is kept.
    fence.dispatch(&[row(Authority::User("u1".into()), Revocation::User, 101)]);
    assert_eq!(revoked_now(&first), Some(Revocation::Session));
    assert_eq!(revoked_now(&second), Some(Revocation::User));
    assert_eq!(revoked_now(&stranger), None);
}

#[test]
fn an_oauth_stream_ends_on_its_token_or_its_grant_and_an_api_key_stream_on_its_key() {
    let fence = Fence::new();
    let oauth = |hash: &str| Admitted {
        user_id: "u1".into(),
        credential: AdmittedCredential::OAuthToken {
            token_hash: hash.into(),
            client_id: "cli".into(),
        },
        organization: None,
    };
    let token = fence.register(&oauth("h1"), snapshot("1:1:"));
    let grant = fence.register(&oauth("h2"), snapshot("1:1:"));
    let key = fence.register(
        &Admitted {
            user_id: "u1".into(),
            credential: AdmittedCredential::ApiKey {
                key_id: "k1".into(),
            },
            organization: None,
        },
        snapshot("1:1:"),
    );

    fence.dispatch(&[row(
        Authority::OAuthToken("h1".into()),
        Revocation::OAuthToken,
        5,
    )]);
    assert_eq!(revoked_now(&token), Some(Revocation::OAuthToken));
    assert_eq!(revoked_now(&grant), None);

    let other_client = Authority::OAuthGrant {
        user_id: "u1".into(),
        client_id: "desktop".into(),
    };
    fence.dispatch(&[row(other_client, Revocation::OAuthGrant, 5)]);
    assert_eq!(revoked_now(&grant), None);
    let same_client = Authority::OAuthGrant {
        user_id: "u1".into(),
        client_id: "cli".into(),
    };
    fence.dispatch(&[row(same_client, Revocation::OAuthGrant, 5)]);
    assert_eq!(revoked_now(&grant), Some(Revocation::OAuthGrant));

    assert_eq!(revoked_now(&key), None);
    fence.dispatch(&[row(Authority::ApiKey("k1".into()), Revocation::ApiKey, 5)]);
    assert_eq!(revoked_now(&key), Some(Revocation::ApiKey));
}

#[test]
fn a_dropped_watch_leaves_no_registration() {
    let fence = Fence::new();
    let watch = fence.register(&session("u1", "s1"), snapshot("1:1:"));
    drop(watch);
    let registry = fence
        .registry
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    assert!(registry.entries.is_empty() && registry.by_key.is_empty());
}

#[test]
fn the_cursor_reads_skipped_numbers_again_until_they_appear_or_age_out() {
    let start = Instant::now();
    let mut cursor = LogCursor::default();
    cursor.record([3, 4, 7].into_iter(), start);
    assert_eq!(cursor.last, Some(7));
    assert_eq!(cursor.gaps.keys().copied().collect::<Vec<_>>(), vec![5, 6]);

    // 6 commits late, alongside a new 9.
    cursor.record([6, 9].into_iter(), start);
    assert_eq!(cursor.last, Some(9));
    assert_eq!(cursor.gaps.keys().copied().collect::<Vec<_>>(), vec![5, 8]);

    cursor.record(std::iter::empty(), start + GAP_LIFETIME);
    assert!(cursor.gaps.is_empty());
}

#[test]
fn a_stream_into_an_organization_ends_on_its_users_removal_or_the_deletion_start() {
    let fence = Fence::new();
    let in_a = |user: &str, session_id: &str| session(user, session_id).in_organization("org-a");
    let removed = fence.register(&in_a("u1", "s1"), snapshot("1:1:"));
    let deleted = fence.register(&in_a("u2", "s2"), snapshot("1:1:"));
    let elsewhere = fence.register(
        &session("u1", "s3").in_organization("org-b"),
        snapshot("1:1:"),
    );
    let unscoped = fence.register(&session("u1", "s4"), snapshot("1:1:"));

    fence.dispatch(&[row(
        Authority::Membership {
            user_id: "u1".into(),
            org_id: "org-a".into(),
        },
        Revocation::Membership,
        5,
    )]);
    assert_eq!(revoked_now(&removed), Some(Revocation::Membership));
    assert_eq!(
        revoked_now(&deleted),
        None,
        "another member's stream runs on"
    );
    assert_eq!(
        revoked_now(&elsewhere),
        None,
        "the user's other organization runs on"
    );
    assert_eq!(revoked_now(&unscoped), None);

    fence.dispatch(&[row(
        Authority::Organization("org-a".into()),
        Revocation::Organization,
        6,
    )]);
    assert_eq!(revoked_now(&deleted), Some(Revocation::Organization));
    assert_eq!(revoked_now(&elsewhere), None);
    assert_eq!(revoked_now(&unscoped), None);
}

#[test]
fn the_log_reads_the_two_organization_kinds_by_their_own_column() {
    let log = |kind: &str, user_id: &str, org_id: Option<&str>| LogRow {
        seq: 1,
        kind: kind.into(),
        credential_id: org_id.unwrap_or("x").into(),
        user_id: user_id.into(),
        org_id: org_id.map(Into::into),
        xact: "7".into(),
    };
    let membership = log("membership", "u1", Some("org-a"))
        .entry()
        .expect("read");
    assert_eq!(
        membership.key,
        Authority::Membership {
            user_id: "u1".into(),
            org_id: "org-a".into(),
        }
    );
    assert_eq!(membership.revocation, Revocation::Membership);
    let organization = log("organization", "", Some("org-a"))
        .entry()
        .expect("read");
    assert_eq!(organization.key, Authority::Organization("org-a".into()));
    assert!(log("organization", "", None).entry().is_none());
}

#[test]
fn only_the_deletion_ends_a_connect_stream_saying_the_organization_is_being_deleted() {
    let deleting = ended_error(Revocation::Organization);
    assert_eq!(deleting.code, connectrpc::ErrorCode::FailedPrecondition);
    assert_eq!(
        deleting.message.as_deref(),
        Some(crate::org::ORGANIZATION_DELETING)
    );
    for revocation in [
        Revocation::Membership,
        Revocation::Session,
        Revocation::User,
    ] {
        let revoked = ended_error(revocation);
        assert_eq!(revoked.code, connectrpc::ErrorCode::PermissionDenied);
        assert_eq!(revoked.message.as_deref(), Some("access revoked"));
    }
}

/// A stream's admission is run again for the same request, which yields no
/// organization; the admission still matches when the user and credential
/// do, and not when either differs.
#[test]
fn the_admission_run_again_matches_on_user_and_credential_not_organization() {
    let admitted = session("user-a", "session-a").in_organization("org-a");
    assert!(session("user-a", "session-a").same_credential(&admitted));
    assert!(!session("user-a", "session-b").same_credential(&admitted));
    assert!(!session("user-b", "session-a").same_credential(&admitted));
}
