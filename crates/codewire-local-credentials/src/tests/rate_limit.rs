//! A refresh the provider rate-limited (#4975; docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "A refresh the provider rate-limited"): one wait, kept by the authority,
//! then one retry whose failure is terminal.

use super::*;

struct Refresh {
    channel_id: Uuid,
    refresh_id: Uuid,
    request_id: Uuid,
}

/// Begin a refresh of the credential bound to `environment_id`.
fn begin(
    authority: &LocalCredentialAuthority<TestProtectedStore>,
    environment_id: &EnvironmentId,
) -> Result<Refresh, LocalCredentialError> {
    let request = operation_lease_request(environment_id);
    let lease = authority.lease_environment_credential_operation(&request)?;
    let refresh = Refresh {
        channel_id: Uuid::new_v4(),
        refresh_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
    };
    match authority.begin_environment_credential_refresh(
        refresh.channel_id,
        refresh.refresh_id,
        refresh.request_id,
        &request,
        &lease.grant,
        lease.material_generation(),
    )? {
        CredentialRefreshAdmission::Reserved(_) => Ok(refresh),
        CredentialRefreshAdmission::Recovered => panic!("nothing to recover"),
    }
}

fn start(authority: &LocalCredentialAuthority<TestProtectedStore>, refresh: &Refresh) {
    authority
        .start_environment_credential_refresh(
            refresh.channel_id,
            refresh.refresh_id,
            refresh.request_id,
        )
        .expect("start refresh");
}

fn rate_limit(
    authority: &LocalCredentialAuthority<TestProtectedStore>,
    refresh: &Refresh,
    wait_seconds: u64,
) -> Result<(), LocalCredentialError> {
    authority.rate_limit_environment_credential_refresh(
        refresh.channel_id,
        refresh.refresh_id,
        refresh.request_id,
        wait_seconds,
    )
}

/// End the credential's wait now.
fn end_wait(authority: &LocalCredentialAuthority<TestProtectedStore>, id: &CredentialId) {
    let changed = authority
        .connection()
        .expect("connection")
        .execute(
            "UPDATE authority_metadata SET value = json_set(value, '$.until_unix_ms', 0)
             WHERE key = ?1",
            [format!("credential_refresh_wait/{}", id.as_str())],
        )
        .expect("end the wait");
    assert_eq!(changed, 1);
}

fn setup(
    name: &str,
) -> (
    TempDir,
    LocalCredentialAuthority<TestProtectedStore>,
    CredentialRecord,
    EnvironmentId,
) {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = LocalCredentialAuthority::open(&authority_root(&temp), store, catalog())
        .expect("open authority");
    let credential = authority
        .add_credential(new_credential(name), material(b"first-oauth-bundle"))
        .expect("add credential");
    let environment_id = environment(&format!("env-{name}"));
    bind_credential(&authority, &environment_id, &credential.metadata.id);
    (temp, authority, credential, environment_id)
}

#[test]
fn a_rate_limited_refresh_keeps_the_sign_in_waits_once_and_its_retry_fails() {
    let (_temp, authority, credential, environment_id) = setup("limited");
    let request = operation_lease_request(&environment_id);
    let first = begin(&authority, &environment_id).expect("begin");
    start(&authority, &first);
    // A wait outside the bounds is held to them.
    rate_limit(&authority, &first, 86_400).expect("rate limit");

    // The sign-in is kept, material and generation included.
    let lease = authority
        .lease_environment_credential_operation(&request)
        .expect("lease during the wait");
    assert_eq!(lease.grant.credential_revocation_generation, 1);
    assert_eq!(lease.with_material(<[u8]>::to_vec), b"first-oauth-bundle");
    // No refresh begins while the wait runs, held at its bound.
    match begin(&authority, &environment_id) {
        Err(LocalCredentialError::CredentialRefreshRateLimited {
            retry_after_seconds,
        }) => assert!(
            (599..=600).contains(&retry_after_seconds),
            "{retry_after_seconds}"
        ),
        Err(other) => panic!("begin during the wait: {other:?}"),
        Ok(_) => panic!("begin during the wait succeeded"),
    }
    // The same attempt cannot be closed twice.
    assert_eq!(
        rate_limit(&authority, &first, 60),
        Err(LocalCredentialError::StaleCredentialRefresh)
    );

    end_wait(&authority, &credential.metadata.id);
    let retry = begin(&authority, &environment_id).expect("the retry begins after the wait");
    start(&authority, &retry);
    assert_eq!(
        rate_limit(&authority, &retry, 60),
        Err(LocalCredentialError::StaleCredentialRefresh)
    );
    let failed = authority
        .fail_environment_credential_refresh(retry.channel_id, retry.refresh_id, retry.request_id)
        .expect("the retry's failure is recorded");
    assert_eq!(failed.metadata.status, CredentialStatus::RefreshFailed);
}

/// A retry cancelled before it started leaves the next refresh the retry.
#[test]
fn the_retry_stays_the_retry_when_it_is_aborted_before_starting() {
    let (_temp, authority, credential, environment_id) = setup("aborted");
    let first = begin(&authority, &environment_id).expect("begin");
    start(&authority, &first);
    rate_limit(&authority, &first, 60).expect("rate limit");
    end_wait(&authority, &credential.metadata.id);

    let aborted = begin(&authority, &environment_id).expect("the retry begins");
    authority
        .abort_environment_credential_refresh(
            aborted.channel_id,
            aborted.refresh_id,
            aborted.request_id,
        )
        .expect("abort before start");
    let retry = begin(&authority, &environment_id).expect("the next refresh begins");
    start(&authority, &retry);
    assert_eq!(
        rate_limit(&authority, &retry, 60),
        Err(LocalCredentialError::StaleCredentialRefresh)
    );
}

/// A published refresh moves the generation, so a wait from before it no
/// longer applies: the next refresh may wait once again.
#[test]
fn a_published_refresh_forgets_the_wait() {
    let (_temp, authority, credential, environment_id) = setup("published");
    let first = begin(&authority, &environment_id).expect("begin");
    start(&authority, &first);
    rate_limit(&authority, &first, 60).expect("rate limit");
    end_wait(&authority, &credential.metadata.id);

    let retry = begin(&authority, &environment_id).expect("the retry begins");
    start(&authority, &retry);
    authority
        .commit_environment_credential_refresh(
            retry.channel_id,
            retry.refresh_id,
            retry.request_id,
            &material(b"refreshed-oauth-bundle"),
        )
        .expect("publish");

    let later = begin(&authority, &environment_id).expect("a later refresh begins");
    start(&authority, &later);
    rate_limit(&authority, &later, 60).expect("a later refresh may wait once");
}
