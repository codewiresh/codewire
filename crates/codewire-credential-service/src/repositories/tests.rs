use super::*;

mod integration;

fn request() -> ListGithubRepositoriesRequest {
    ListGithubRepositoriesRequest {
        profile_id: "11111111-1111-4111-8111-111111111111".into(),
        profile_revision: 7,
        page_size: 50,
        ..Default::default()
    }
}

#[test]
fn selection_rejects_noncanonical_or_unbounded_inputs() {
    assert_eq!(Selection::parse(request()).unwrap().page, 1);
    let mut default = request();
    default.page_size = 0;
    assert_eq!(
        Selection::parse(default).unwrap().page_size,
        DEFAULT_PAGE_SIZE
    );
    for id in [
        "",
        "not-a-profile",
        "00000000-0000-0000-0000-000000000000",
        "11111111111141118111111111111111",
    ] {
        let mut value = request();
        value.profile_id = id.into();
        assert!(matches!(Selection::parse(value), Err(Error::InvalidInput)));
    }
    for revision in [0, i64::MAX as u64 + 1, u64::MAX] {
        let mut value = request();
        value.profile_revision = revision;
        assert!(matches!(Selection::parse(value), Err(Error::InvalidInput)));
    }
    for size in [-1, 101, i32::MAX] {
        let mut value = request();
        value.page_size = size;
        assert!(matches!(Selection::parse(value), Err(Error::InvalidInput)));
    }
    for token in [
        "x".repeat(129),
        "https://attacker.example".into(),
        format!("v1.01.50.{}", "a".repeat(64)),
        format!("v1.2.100.{}", "a".repeat(64)),
        format!("v1.10001.50.{}", "a".repeat(64)),
    ] {
        let mut value = request();
        value.page_token = token;
        assert!(matches!(Selection::parse(value), Err(Error::InvalidInput)));
    }
}

#[test]
fn continuation_pages_accept_only_the_inclusive_supported_range() {
    for page in [2, github::MAX_PAGE] {
        let mut value = request();
        value.page_token = format!("v1.{page}.50.{}", "a".repeat(64));
        assert_eq!(Selection::parse(value).unwrap().page, page);
    }
    for page in [0, 1, github::MAX_PAGE + 1, u32::MAX] {
        let mut value = request();
        value.page_token = format!("v1.{page}.50.{}", "a".repeat(64));
        assert!(matches!(Selection::parse(value), Err(Error::InvalidInput)));
    }
}

#[test]
fn closed_errors_never_echo_request_or_provider_details() {
    for value in [
        Error::InvalidInput,
        Error::Denied,
        Error::NotFound,
        Error::ProfileChanged,
        Error::NotConnected,
        Error::CredentialChanged,
        Error::ProviderDenied,
        Error::RateLimited,
        Error::Unavailable,
        Error::Cancelled,
        Error::Expired,
    ] {
        let error = wire::error(value);
        let message = error.message.expect("closed message");
        assert!(!message.contains("https://"));
        assert!(!message.contains("token"));
    }
}
