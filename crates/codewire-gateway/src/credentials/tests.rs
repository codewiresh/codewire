//! Shared projected-identity helpers of the hosted credential relay.

use super::*;
use std::time::Duration;

const WORKSPACE_ONE: &str = "Bearer workspace.projected.one";
const GATEWAY_ONE: &str = "gateway.projected.one";

#[test]
fn metadata_is_sensitive_and_binary_only() {
    let metadata = credential_metadata(GATEWAY_ONE, WORKSPACE_ONE.as_bytes()).unwrap();
    assert_eq!(metadata.len(), 2);
    let gateway = metadata.get("authorization").unwrap();
    assert!(gateway.is_sensitive());
    assert_eq!(gateway.to_str().unwrap(), format!("Bearer {GATEWAY_ONE}"));
    let workspace = metadata.get_bin(WORKSPACE_AUTHORIZATION).unwrap();
    assert!(workspace.is_sensitive());
    assert_eq!(
        workspace.to_bytes().unwrap().as_ref(),
        WORKSPACE_ONE.as_bytes()
    );
    assert!(!metadata.contains_key("x-codewire-workspace-authorization"));
}

#[tokio::test]
async fn gateway_token_must_be_one_bounded_canonical_regular_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("token");
    std::fs::write(&path, GATEWAY_ONE).unwrap();
    assert_eq!(
        read_gateway_token(&path).await.unwrap().as_str(),
        GATEWAY_ONE
    );
    for invalid in [
        String::new(),
        "gateway token".into(),
        "x".repeat(MAX_TOKEN_BYTES + 1),
    ] {
        std::fs::write(&path, invalid).unwrap();
        assert_eq!(
            read_gateway_token(&path).await.unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(
        read_gateway_token(directory.path()).await.unwrap_err(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[cfg(unix)]
#[tokio::test]
async fn projected_gateway_fifo_is_denied_without_stranding_file_open() {
    use std::os::unix::ffi::OsStrExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("token");
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: CString is NUL-terminated and lives through this call; the path
    // is an exact file in this fixture's private, owned temporary directory.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let result = tokio::time::timeout(Duration::from_secs(1), read_gateway_token(&path))
        .await
        .expect("FIFO open blocked instead of failing closed");
    assert_eq!(result.unwrap_err(), StatusCode::SERVICE_UNAVAILABLE);
}
