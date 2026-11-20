//! The desktop calls against a synthetic server: each goes to its own route
//! with the caller's credential, and a running desktop arrives whole.

use buffa::Message as _;
use buffa_types::Timestamp;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::{ClientConfig, StaticTokenProvider};

const PASSWORD: &str = "a1b2c3d4";

fn running() -> EnvironmentDesktop {
    EnvironmentDesktop {
        state: EnvironmentDesktopState::Running.into(),
        running: Some(EnvironmentDesktopRunning {
            display: ":1".into(),
            port: 5901,
            started_at: Some(Timestamp::from_unix(1_795_000_000, 0)).into(),
            viewer_password: PASSWORD.into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

fn stopped() -> EnvironmentDesktop {
    EnvironmentDesktop {
        state: EnvironmentDesktopState::Stopped.into(),
        ..Default::default()
    }
}

async fn serve(server: &MockServer, rpc: &str, body: Vec<u8>) {
    Mock::given(method("POST"))
        .and(path(format!(
            "/codewire.v1.EnvironmentDesktopService/{rpc}"
        )))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/proto")
                .set_body_bytes(body),
        )
        .expect(1)
        .mount(server)
        .await;
}

fn client(server: &MockServer) -> CodewireClient {
    CodewireClient::with_http(
        ClientConfig::new(server.uri()).expect("server URL"),
        StaticTokenProvider::new("test-token").expect("token"),
        reqwest::Client::new(),
    )
    .expect("client")
}

#[tokio::test]
async fn each_desktop_call_reaches_its_route_and_a_running_desktop_arrives_whole() {
    let server = MockServer::start().await;
    serve(
        &server,
        "StartDesktop",
        StartDesktopResponse {
            desktop: Some(running()).into(),
            ..Default::default()
        }
        .encode_to_vec(),
    )
    .await;
    serve(
        &server,
        "GetDesktop",
        GetDesktopResponse {
            desktop: Some(running()).into(),
            ..Default::default()
        }
        .encode_to_vec(),
    )
    .await;
    serve(
        &server,
        "StopDesktop",
        StopDesktopResponse {
            desktop: Some(stopped()).into(),
            ..Default::default()
        }
        .encode_to_vec(),
    )
    .await;
    let client = client(&server);
    let ids = || ("org_123".to_owned(), "env_123".to_owned());

    let (org_id, environment_id) = ids();
    let started = client
        .start_desktop(StartDesktopRequest {
            org_id,
            environment_id,
            ..Default::default()
        })
        .await
        .expect("start");
    assert_eq!(started.desktop.as_option(), Some(&running()));
    // The password is the caller's to use and never in debug output.
    assert!(!format!("{started:?}").contains(PASSWORD));

    let (org_id, environment_id) = ids();
    let read = client
        .get_desktop(GetDesktopRequest {
            org_id,
            environment_id,
            ..Default::default()
        })
        .await
        .expect("get");
    let details = read
        .desktop
        .as_option()
        .and_then(|desktop| desktop.running.as_option())
        .expect("running details");
    assert_eq!(details.viewer_password, PASSWORD);
    assert_eq!(details.port, 5901);

    let (org_id, environment_id) = ids();
    let stopped_answer = client
        .stop_desktop(StopDesktopRequest {
            org_id,
            environment_id,
            ..Default::default()
        })
        .await
        .expect("stop");
    assert_eq!(stopped_answer.desktop.as_option(), Some(&stopped()));
}
