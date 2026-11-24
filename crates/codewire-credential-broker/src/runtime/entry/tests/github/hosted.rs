//! GitHub's two hosts behind a hosted Sandbox's front door (#4001): nothing
//! goes untouched, so a Git request that carries no placeholder gets
//! GitHub's own challenge where the binding selects the `github` slot, and
//! every other such request is refused; a lease whose placeholder key could
//! not be read refuses the request on either host, as on Anthropic's route.

use super::*;

/// A hosted broker whose binding selects the `github` slot.
fn challenging(recorded: &Recorded) -> OpenAiBroker<Authority, Upstream> {
    recorded
        .broker_without_answer()
        .with_untouched_forwards_refused_challenging_git()
}

fn git(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, String)],
) -> v1::CredentialBridgeRequest {
    github("github.com", method, path, query, headers, b"")
}

/// Git's smart-HTTP requests to `github.com` with no placeholder-shaped
/// value, anonymous or with the user's own token: 401 with GitHub's Basic
/// challenge and a fixed body, no lease, and nothing sent.
#[tokio::test]
async fn gits_request_without_a_placeholder_gets_githubs_challenge() {
    let own = [("authorization", basic(USERS_TOKEN))];
    for (method, path, query, headers) in [
        (
            "GET",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
            &[][..],
        ),
        (
            "GET",
            "/owner/repo/info/refs",
            "service=git-receive-pack",
            &[][..],
        ),
        (
            "GET",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
            &own[..],
        ),
        ("POST", "/owner/repo.git/git-upload-pack", "", &[][..]),
        ("POST", "/owner/repo.git/git-receive-pack", "", &own[..]),
    ] {
        let recorded = ours();
        let broker = challenging(&recorded);
        let (status, headers, body) = collect(
            broker
                .execute_front_door(git(method, path, query, headers))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(
            headers[http::header::WWW_AUTHENTICATE],
            "Basic realm=\"GitHub\""
        );
        assert_eq!(headers[http::header::CACHE_CONTROL], "no-store");
        assert_eq!(
            headers[http::header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert!(
            contains(&body, "Authentication required."),
            "{method} {path}"
        );
        assert!(!contains(&body, USERS_TOKEN));
        assert_eq!(recorded.leases(), 0, "{method} {path}");
        assert!(recorded.outbound().is_empty(), "{method} {path}");
    }
}

/// A streamed push body is answered the same, before anything is read or
/// sent.
#[tokio::test]
async fn a_streamed_git_push_without_a_placeholder_gets_the_challenge() {
    let recorded = ours();
    let broker = challenging(&recorded);
    let mut push = git("POST", "/owner/repo.git/git-receive-pack", "", &[]);
    push.streamed_body = true;
    let (status, headers, _) = collect(
        broker
            .execute_front_door_streamed(push, streamed(vec![vec![b'p'; 1024]]), &Arc::default())
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers[http::header::WWW_AUTHENTICATE],
        "Basic realm=\"GitHub\""
    );
    assert_eq!(recorded.leases(), 0);
    assert!(recorded.outbound().is_empty());
}

/// Each condition on its own side: `api.github.com`, a service Git does not
/// fetch or push with, an extra path suffix and a path off Git's grammar are
/// refused `selected_credential_only` as before; so is Git's own request on
/// a broker whose binding does not select the `github` slot.
#[tokio::test]
async fn every_other_request_without_a_placeholder_is_refused() {
    let selecting = ours();
    let not_selecting = ours();
    let unselected = not_selecting
        .broker_without_answer()
        .with_untouched_forwards_refused();
    let broker = challenging(&selecting);
    for request in [
        github("api.github.com", "GET", "/user", "", &[], b""),
        github(
            "api.github.com",
            "GET",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
            &[],
            b"",
        ),
        git(
            "GET",
            "/owner/repo.git/info/refs",
            "service=git-upload-archive",
            &[],
        ),
        git("GET", "/owner/repo.git/info/refs", "", &[]),
        git(
            "GET",
            "/owner/repo.git/info/refs/x",
            "service=git-upload-pack",
            &[],
        ),
        git("POST", "/owner/repo.git/git-upload-pack/x", "", &[]),
        git("POST", "/owner/repo.git/info/lfs/objects/batch", "", &[]),
        git("GET", "/owner/repo/releases/download/v1/a.tar.gz", "", &[]),
    ] {
        let target = format!(
            "{}{}?{}",
            request.intercepted_host, request.path, request.query
        );
        let refused = broker.execute_front_door(request).await;
        assert_eq!(
            refused.err(),
            Some(BrokerRequestError::SelectedCredentialOnly),
            "{target}"
        );
    }
    let refused = unselected
        .execute_front_door(git(
            "GET",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
            &[],
        ))
        .await;
    assert_eq!(
        refused.err(),
        Some(BrokerRequestError::SelectedCredentialOnly)
    );
    for recorded in [selecting, not_selecting] {
        assert_eq!(recorded.leases(), 0);
        assert!(recorded.outbound().is_empty());
    }
}

/// A request that carries a placeholder is never challenged: another
/// environment's, once a lease shows it is not ours, is refused like any
/// untouched forward, and this environment's is served.
#[tokio::test]
async fn a_request_carrying_a_placeholder_is_never_challenged() {
    let refs = |placeholder| {
        git(
            "GET",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
            &[("authorization", basic(placeholder))],
        )
    };
    let recorded = ours();
    let broker = challenging(&recorded);
    let refused = broker.execute_front_door(refs(THEIRS)).await;
    assert_eq!(
        refused.err(),
        Some(BrokerRequestError::SelectedCredentialOnly)
    );
    assert_eq!(recorded.leases(), 1);
    assert!(recorded.outbound().is_empty());

    let (status, _, _) = collect(broker.execute_front_door(refs(OURS)).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(recorded.leases(), 2);
    assert_eq!(recorded.forwarded(), 0);
    assert!(!carries(&recorded.outbound()[0], OURS));
}

/// A lease whose placeholder key could not be read refuses the request on
/// either host, this environment's placeholder and another's alike, and
/// nothing is sent, on a hosted broker and one that may forward (#5087).
#[tokio::test]
async fn a_failed_key_read_refuses_githubs_requests_whatever_they_carry() {
    for hosted in [false, true] {
        let recorded = Recorded {
            placeholder_failed: true,
            ..Recorded::default()
        };
        let broker = if hosted {
            challenging(&recorded)
        } else {
            recorded.broker()
        };
        let mut sent = 0;
        for presented in [OURS, THEIRS] {
            for mut request in on_the_grammar() {
                let credential = if request.intercepted_host == "github.com" {
                    basic(presented)
                } else {
                    format!("token {presented}")
                };
                request.headers = vec![v1::CredentialHttpHeader {
                    name: "authorization".into(),
                    value: credential.into_bytes(),
                }];
                let host = request.intercepted_host.clone();
                let answer = broker.execute_front_door(request).await;
                sent += 1;
                assert_eq!(
                    answer.err(),
                    Some(BrokerRequestError::AuthorityUnavailable),
                    "{host}: refused, never forwarded (hosted: {hosted})"
                );
            }
        }
        assert_eq!(recorded.leases(), sent);
        assert_eq!(recorded.forwarded(), 0);
        assert!(recorded.outbound().is_empty());
    }
}
