//! The organization, project and personal secret cores bind a secret only
//! for whoever may set it today, refuse a change that needs the value with
//! `secret_value_required` and a bound rename with `secret_bound_rename`,
//! leave no organization lease unresolved for a refusal, and list each
//! binding (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "Host-bound
//! application secrets").

use std::sync::Arc;

use axum::http::StatusCode;
use codewire_access::{ReservedHosts, StoredBinding, StoredPresentation};
use codewire_protected_store::secret_envelope::TestKekProvider;
use codewire_server_core::AppError;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::unresolved_organization_mutation_leases;
use uuid::Uuid;

use super::super::ApiState;
use super::super::secret_projects::{
    list_project_secrets_core, rename_project_secret_core, set_project_secret_core,
};
use super::{
    SECRET_BINDING_UNAVAILABLE, SECRET_BOUND_RENAME, SECRET_VALUE_REQUIRED, list_secrets_core,
    list_user_secrets_core, rename_secret_core, rename_user_secret_core, set_secret_core,
    set_user_secret_core,
};
use crate::worker::secrets::{BindingWrite, SecretStore};

const VALUE: &str = "synthetic-bound-core-value";
const RESERVED: &str = "openbao.sandbox.example.dev";

/// One organization with an owner, an admin and a member, and one secret
/// project; every identifier starts with the fixture's.
struct Fixture {
    state: ApiState,
    id: String,
    project_id: String,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("secret binding core tests require the disposable TEST_DATABASE_URL");
        codewire_server_core::migrate::ensure_schema(&url)
            .await
            .unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .unwrap();
        let mut state = super::super::test_state::offline(pool.clone()).await;
        state.secrets = Arc::new(
            SecretStore::new_for_test(pool.clone(), Arc::new(TestKekProvider))
                .with_reserved_for_test(ReservedHosts::new([RESERVED]).unwrap()),
        );
        let id = format!("bound-{}", Uuid::new_v4().simple());
        for role in ["owner", "admin", "member"] {
            let user_id = format!("{id}-{role}");
            sqlx::query(
                "INSERT INTO users (id, email, name, email_verified) \
                 VALUES ($1, $2, 'Bound secret core test', true)",
            )
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ($1, 'Bound secret core test', $1, $1 || '-owner')",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
        for role in ["owner", "admin", "member"] {
            sqlx::query(
                "INSERT INTO org_members (id, org_id, user_id, role) \
                 VALUES ($1 || '-' || $2, $1, $1 || '-' || $2, $2)",
            )
            .bind(&id)
            .bind(role)
            .execute(&pool)
            .await
            .unwrap();
        }
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO secret_projects (org_id, name) VALUES ($1, 'bound') RETURNING id",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        Self {
            state,
            id,
            project_id,
        }
    }

    fn user(&self, role: &str) -> AuthUser {
        AuthUser {
            user_id: format!("{}-{role}", self.id),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        }
    }

    async fn assert_no_unresolved_leases(&self) {
        let unresolved = unresolved_organization_mutation_leases(&self.state.pool, &self.id)
            .await
            .unwrap();
        assert!(unresolved.is_empty(), "{unresolved:?}");
    }

    async fn cleanup(self) {
        let pool = &self.state.pool;
        let mut paths = vec![
            format!("/org-secrets/{}", self.id),
            format!("/projects/{}/{}", self.id, self.project_id),
        ];
        paths.extend(["owner", "admin", "member"].map(|role| format!("/users/{}-{role}", self.id)));
        for path in paths {
            self.state.secrets.delete_path(&path).await.unwrap();
        }
        for (table, column) in [
            ("organization_mutation_leases", "organization_id"),
            ("secret_projects", "org_id"),
            ("organizations", "id"),
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE {column} = $1"))
                .bind(&self.id)
                .execute(pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM users WHERE id LIKE $1 || '-%'")
            .bind(&self.id)
            .execute(pool)
            .await
            .unwrap();
        pool.close().await;
    }
}

fn binding(hosts: &[&str]) -> StoredBinding {
    StoredBinding {
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        presentation: StoredPresentation::Header {
            headers: vec!["Authorization".into()],
            scheme: Some("Bearer".into()),
        },
        prefix: None,
        preset: None,
    }
}

fn bind(hosts: &[&str]) -> BindingWrite {
    BindingWrite::Bind(binding(hosts))
}

/// The status and code of a refusal, and its text.
fn refusal(result: Result<(), AppError>) -> (StatusCode, &'static str, String) {
    match result.unwrap_err() {
        AppError::Coded {
            status,
            code,
            detail,
        } => (status, code, detail.into_owned()),
        other => (other.status(), "", other.to_string()),
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_organization_secrets_bind_for_owners_and_admins_only() {
    let fixture = Fixture::new().await;
    let state = &fixture.state;
    let (owner, admin, member) = (
        fixture.user("owner"),
        fixture.user("admin"),
        fixture.user("member"),
    );
    let org = fixture.id.as_str();
    let two_hosts = ["api.fancy.com", "uploads.fancy.com"];

    assert_eq!(
        refusal(set_secret_core(state, &member, org, "TOKEN", VALUE, bind(&two_hosts)).await).0,
        StatusCode::FORBIDDEN
    );
    set_secret_core(state, &owner, org, "TOKEN", VALUE, bind(&two_hosts))
        .await
        .unwrap();
    assert_eq!(
        refusal(set_secret_core(state, &member, org, "TOKEN", "", bind(&["api.fancy.com"])).await)
            .0,
        StatusCode::FORBIDDEN,
        "a member changes no binding, even one that needs no value"
    );
    set_secret_core(state, &admin, org, "TOKEN", "", bind(&["api.fancy.com"]))
        .await
        .unwrap();

    let (status, code, detail) =
        refusal(set_secret_core(state, &admin, org, "TOKEN", "", bind(&two_hosts)).await);
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, SECRET_VALUE_REQUIRED)
    );
    assert_eq!(detail, "adding a host needs the secret's value again");
    let (status, code, detail) =
        refusal(set_secret_core(state, &owner, org, "OTHER", VALUE, bind(&[RESERVED])).await);
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, "bound_host_reserved")
    );
    assert_eq!(
        detail,
        format!("{RESERVED} can't be bound: Codewire serves it itself")
    );
    let (status, code, detail) =
        refusal(rename_secret_core(state, &owner, org, "TOKEN", "RENAMED").await);
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, SECRET_BOUND_RENAME)
    );
    assert_eq!(
        detail,
        "a bound secret can't be renamed; set the new key with its value, then delete the old one"
    );
    fixture.assert_no_unresolved_leases().await;

    let listed = list_secrets_core(state, &member, org)
        .await
        .unwrap()
        .secrets;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, "TOKEN");
    assert_eq!(listed[0].binding, Some(binding(&["api.fancy.com"])));
    assert_eq!(listed[0].binding_generation, 1);
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_an_empty_value_for_a_plain_secret_is_refused_as_before() {
    let fixture = Fixture::new().await;
    let state = &fixture.state;
    let owner = fixture.user("owner");
    let org = fixture.id.as_str();
    set_secret_core(state, &owner, org, "PLAIN", VALUE, BindingWrite::Keep)
        .await
        .unwrap();
    for write in [BindingWrite::Keep, BindingWrite::Plain] {
        let (status, code, detail) =
            refusal(set_secret_core(state, &owner, org, "PLAIN", "", write).await);
        assert_eq!((status, code), (StatusCode::BAD_REQUEST, ""));
        assert!(
            detail.contains("secret value must be non-empty"),
            "{detail}"
        );
    }
    fixture.assert_no_unresolved_leases().await;
    let listed = list_secrets_core(state, &owner, org).await.unwrap().secrets;
    assert_eq!(
        (listed[0].binding.as_ref(), listed[0].binding_generation),
        (None, 0)
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_project_secrets_bind_for_owners_and_admins_only() {
    let fixture = Fixture::new().await;
    let state = &fixture.state;
    let (owner, member) = (fixture.user("owner"), fixture.user("member"));
    let (org, project) = (fixture.id.as_str(), fixture.project_id.as_str());
    let hosts = ["api.fancy.com"];

    assert_eq!(
        refusal(
            set_project_secret_core(state, &member, org, project, "TOKEN", VALUE, bind(&hosts))
                .await
        )
        .0,
        StatusCode::FORBIDDEN
    );
    let (_, code, _) = refusal(
        set_project_secret_core(state, &owner, org, project, "TOKEN", "", bind(&hosts)).await,
    );
    assert_eq!(code, SECRET_VALUE_REQUIRED);
    set_project_secret_core(state, &owner, org, project, "TOKEN", VALUE, bind(&hosts))
        .await
        .unwrap();
    let (_, code, _) = refusal(
        set_project_secret_core(
            state,
            &owner,
            org,
            project,
            "TOKEN",
            "",
            BindingWrite::Plain,
        )
        .await,
    );
    assert_eq!(
        code, SECRET_VALUE_REQUIRED,
        "making it plain needs the value"
    );
    let (_, code, _) =
        refusal(rename_project_secret_core(state, &owner, org, project, "TOKEN", "RENAMED").await);
    assert_eq!(code, SECRET_BOUND_RENAME);
    fixture.assert_no_unresolved_leases().await;

    let listed = list_project_secrets_core(state, &member, org, project)
        .await
        .unwrap()
        .secrets;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].binding, Some(binding(&hosts)));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_a_personal_secret_binds_for_its_user() {
    let fixture = Fixture::new().await;
    let state = &fixture.state;
    let user = fixture.user("member");
    let hosts = ["api.fancy.com", "uploads.fancy.com"];

    let (_, code, _) = refusal(set_user_secret_core(state, &user, "TOKEN", "", bind(&hosts)).await);
    assert_eq!(code, SECRET_VALUE_REQUIRED);
    set_user_secret_core(state, &user, "TOKEN", VALUE, bind(&hosts))
        .await
        .unwrap();
    set_user_secret_core(state, &user, "TOKEN", "", bind(&["api.fancy.com"]))
        .await
        .unwrap();
    let (status, code, _) =
        refusal(set_user_secret_core(state, &user, "OTHER", VALUE, bind(&["github.com"])).await);
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, "bound_host_provider")
    );
    let (_, code, _) = refusal(rename_user_secret_core(state, &user, "TOKEN", "RENAMED").await);
    assert_eq!(code, SECRET_BOUND_RENAME);

    let listed = list_user_secrets_core(state, &user).await.unwrap().secrets;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].binding, Some(binding(&["api.fancy.com"])));
    assert!(
        list_user_secrets_core(state, &fixture.user("owner"))
            .await
            .unwrap()
            .secrets
            .is_empty(),
        "another user sees none of it"
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn db_binding_is_refused_while_host_bound_secrets_are_off() {
    let mut fixture = Fixture::new().await;
    let pool = fixture.state.pool.clone();
    fixture.state.secrets = Arc::new(
        SecretStore::new_for_test(pool, Arc::new(TestKekProvider))
            .with_bound_secrets_for_test(false),
    );
    let state = &fixture.state;
    let owner = fixture.user("owner");
    let org = fixture.id.as_str();
    let (status, code, _) = refusal(
        set_secret_core(state, &owner, org, "TOKEN", VALUE, bind(&["api.fancy.com"])).await,
    );
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, SECRET_BINDING_UNAVAILABLE)
    );
    set_secret_core(state, &owner, org, "TOKEN", VALUE, BindingWrite::Keep)
        .await
        .unwrap();
    let listed = list_secrets_core(state, &owner, org).await.unwrap().secrets;
    assert_eq!(
        listed
            .iter()
            .find(|secret| secret.key == "TOKEN")
            .unwrap()
            .binding,
        None
    );
}
