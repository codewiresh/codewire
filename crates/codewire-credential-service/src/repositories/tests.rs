use super::*;

mod integration;

fn request() -> ListGithubRepositoriesRequest {
    ListGithubRepositoriesRequest {
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
    for size in [-1, 101, i32::MAX] {
        let mut value = request();
        value.page_size = size;
        assert!(matches!(Selection::parse(value), Err(Error::InvalidInput)));
    }
    for token in [
        "x".repeat(129),
        "https://attacker.example".into(),
        format!("v2.01.50.{}", "a".repeat(64)),
        format!("v2.2.100.{}", "a".repeat(64)),
        format!("v2.10001.50.{}", "a".repeat(64)),
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
        value.page_token = format!("v2.{page}.50.{}", "a".repeat(64));
        assert_eq!(Selection::parse(value).unwrap().page, page);
    }
    for page in [0, 1, github::MAX_PAGE + 1, u32::MAX] {
        let mut value = request();
        value.page_token = format!("v2.{page}.50.{}", "a".repeat(64));
        assert!(matches!(Selection::parse(value), Err(Error::InvalidInput)));
    }
}

#[test]
fn closed_errors_never_echo_request_or_provider_details() {
    for value in [
        Error::InvalidInput,
        Error::Denied,
        Error::NotFound,
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
