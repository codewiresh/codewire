//! GetEnvironmentProjectSpec: the saved spec for `cw export`. Every caller is
//! answered exactly as GetEnvironment answers it, and a declared environment
//! value never leaves; only its name does.

use reqwest::StatusCode;
use serde_json::{Value, json};

use super::{Auth, Harness, PRIMARY_ORG};

const ENVIRONMENT_SERVICE: &str = "codewire.v1.EnvironmentService";
/// The seed declares `SYNTHETIC_CANARY` in this environment's saved spec and
/// grants the member fixture viewer access to it.
const VIEWER_ENV: &str = "env_port_contract_viewer";
const UNGRANTED_ENV: &str = "env_environment_contract_read";
const MISSING_ENV: &str = "env_project_spec_contract_missing";
const CANARY_VALUE: &str = "never-return-this-value";

fn request(environment_id: &str) -> Value {
    json!({"orgId": PRIMARY_ORG, "environmentId": environment_id})
}

async fn saved_spec(harness: &Harness, auth: Auth, label: &str) -> Value {
    let response = harness
        .connect_json(
            ENVIRONMENT_SERVICE,
            "GetEnvironmentProjectSpec",
            request(VIEWER_ENV),
            auth,
        )
        .await;
    response.assert_status(StatusCode::OK, label);
    assert!(
        !String::from_utf8_lossy(&response.body).contains(CANARY_VALUE),
        "{label} returned a declared environment value"
    );
    response.json()
}

pub(super) async fn run(harness: &Harness) {
    for (auth, label) in [
        (Auth::Admin, "GetEnvironmentProjectSpec as the creator"),
        (Auth::User, "GetEnvironmentProjectSpec as a viewer"),
    ] {
        let body = saved_spec(harness, auth, label).await;
        assert_eq!(
            body["withheldEnvironmentKeys"],
            json!(["SYNTHETIC_CANARY"]),
            "{label}: {body}"
        );
        let spec = &body["projectSpec"];
        assert_eq!(spec["schemaVersion"], 1, "{label}: {body}");
        assert_eq!(spec["workingDirectory"], "/workspace", "{label}: {body}");
        assert!(spec.get("environment").is_none(), "{label}: {body}");
    }

    // Refusals are GetEnvironment's own, status and code alike.
    for (auth, environment_id) in [
        (Auth::User, UNGRANTED_ENV),
        (Auth::Admin, MISSING_ENV),
        (Auth::None, VIEWER_ENV),
    ] {
        let expected = harness
            .connect_json(
                ENVIRONMENT_SERVICE,
                "GetEnvironment",
                request(environment_id),
                auth,
            )
            .await;
        let got = harness
            .connect_json(
                ENVIRONMENT_SERVICE,
                "GetEnvironmentProjectSpec",
                request(environment_id),
                auth,
            )
            .await;
        assert!(
            !expected.status.is_success(),
            "GetEnvironment unexpectedly allowed {environment_id}"
        );
        assert_eq!(got.status, expected.status, "{environment_id}");
        assert_eq!(
            got.json()["code"],
            expected.json()["code"],
            "{environment_id}"
        );
    }
}
