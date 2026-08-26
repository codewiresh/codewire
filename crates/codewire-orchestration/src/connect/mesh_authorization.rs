//! Cluster-local canonical authorization receiver for hosted Mesh.
//!
//! WI-4A provided the receiver and its generated-service proof. WI-4B owns
//! the runtime mount, Mesh caller, and explicit hosted network ownership
//! bridge that consume this unchanged private service.

use std::sync::Arc;

use codewire_proto::codewire::internal::v1::{
    MeshAuthorizationContext, MeshAuthorizationCredentialKind, MeshAuthorizationPrincipalKind,
    MeshAuthorizationService, ResolveMeshAuthorizationRequest, ResolveMeshAuthorizationResponse,
};
use codewire_proto::codewire::v1::OrgRole;
use codewire_server_core::AppError;
use codewire_server_core::connect::{
    MeshAuthorizationPrincipal, mesh_authorization_principal, rpc_app_error,
};
use codewire_server_core::org::user_org_role;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

/// Exact identity bound into the private HMAC service credential.
pub const MESH_AUTHORIZATION_CALLER: &str = "codewire-mesh";
/// Exact generated procedure bound into the private HMAC service credential.
pub const MESH_AUTHORIZATION_METHOD: &str =
    "codewire.internal.v1.MeshAuthorizationService/ResolveMeshAuthorization";

/// Builds the generated private service router.
///
/// The caller must mount it only through
/// `AppBuilder::with_unary_connect_routes_mesh_authorization`; this service
/// intentionally contains no raw-header or HMAC parsing path.
pub fn router(pool: PgPool) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(MeshAuthorizationConnectService { pool }))
}

struct MeshAuthorizationConnectService {
    pool: PgPool,
}

#[allow(refining_impl_trait)]
impl MeshAuthorizationService for MeshAuthorizationConnectService {
    async fn resolve_mesh_authorization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ResolveMeshAuthorizationRequest>,
    ) -> ServiceResult<ResolveMeshAuthorizationResponse> {
        let org_id = request.view().org_id.to_string();
        let context = resolve_mesh_authorization(&self.pool, &ctx, &org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ResolveMeshAuthorizationResponse {
            context: Some(context).into(),
            ..Default::default()
        })
    }
}

async fn resolve_mesh_authorization(
    pool: &PgPool,
    ctx: &RequestContext,
    org_id: &str,
) -> Result<MeshAuthorizationContext, AppError> {
    if org_id.trim().is_empty() {
        return Err(AppError::BadRequest("org_id is required".into()));
    }

    match mesh_authorization_principal(ctx).map_err(|_| AppError::Unauthorized)? {
        MeshAuthorizationPrincipal::User { user, credential } => {
            // API keys are exactly-one-organization machine credentials. This
            // check deliberately precedes membership lookup: a key owner who
            // belongs to several organizations must not borrow another
            // membership through the Mesh receiver.
            if !user.permits_organization(org_id) {
                return Err(AppError::Forbidden);
            }
            let role = user_org_role(pool, user, org_id)
                .await?
                .ok_or(AppError::Forbidden)?;
            Ok(MeshAuthorizationContext {
                principal_id: user.user_id.clone(),
                principal_kind: MeshAuthorizationPrincipalKind::User.into(),
                org_id: org_id.to_owned(),
                role: proto_role(&role)?.into(),
                credential_kind: credential_kind(credential).into(),
                ..Default::default()
            })
        }
        MeshAuthorizationPrincipal::Environment(environment) => {
            if environment.organization_id != org_id {
                return Err(AppError::Forbidden);
            }
            Ok(MeshAuthorizationContext {
                principal_id: environment.environment_id.clone(),
                principal_kind: MeshAuthorizationPrincipalKind::Environment.into(),
                org_id: org_id.to_owned(),
                // Environment tokens carry no user membership. The typed
                // principal and credential kind preserve that distinction;
                // member is the least-privileged role spelling for consumers
                // that require a role field.
                role: OrgRole::Member.into(),
                credential_kind: MeshAuthorizationCredentialKind::EnvironmentToken.into(),
                ..Default::default()
            })
        }
    }
}

fn credential_kind(
    credential: &codewire_server_core::auth::CredentialContext,
) -> MeshAuthorizationCredentialKind {
    match credential {
        codewire_server_core::auth::CredentialContext::SessionCookie => {
            MeshAuthorizationCredentialKind::SessionCookie
        }
        codewire_server_core::auth::CredentialContext::ApiKey { .. } => {
            MeshAuthorizationCredentialKind::ApiKey
        }
        codewire_server_core::auth::CredentialContext::OidcAccessToken { .. } => {
            MeshAuthorizationCredentialKind::OauthBearer
        }
    }
}

fn proto_role(role: &str) -> Result<OrgRole, AppError> {
    match role {
        "owner" => Ok(OrgRole::Owner),
        "admin" => Ok(OrgRole::Admin),
        "member" => Ok(OrgRole::Member),
        _ => Err(AppError::InternalMsg(
            "invalid stored organization role".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine as _;
    use chrono::Utc;
    use codewire_proto::codewire::internal::v1::{
        MeshAuthorizationServiceClient, ResolveMeshAuthorizationRequest,
    };
    use codewire_server_core::AppBuilder;
    use codewire_server_core::auth::{
        AuthState, api_key_prefix, generate_api_key, hash_api_key, hash_oauth_token,
        hash_session_token,
    };
    use codewire_server_core::connect::{
        MESH_FORWARDED_AUTHORIZATION_METADATA, MESH_FORWARDED_SESSION_METADATA,
        MeshAuthorizationLayer,
    };
    use codewire_server_core::internal_hmac::issue_internal_hmac_token;
    use connectrpc::CodecFormat;
    use connectrpc::client::{ClientConfig, HttpClient};
    use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
    use sqlx::postgres::PgPoolOptions;
    use std::net::SocketAddr;

    const HMAC_SECRET: &str = "mesh-authorization-contract-test-hmac-secret";

    #[derive(Debug)]
    struct Fixture {
        user_id: String,
        org_id: String,
        other_org_id: String,
        unrelated_org_id: String,
        session: String,
        api_key: String,
        revoked_api_key: String,
        oauth: String,
        identity_oauth: String,
        expired_oauth: String,
        environment_token: String,
        destroying_environment_token: String,
    }

    #[tokio::test]
    #[ignore = "requires the bounded PostgreSQL integration harness"]
    async fn generated_mesh_authorization_service_enforces_the_canonical_matrix() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set by the bounded PostgreSQL integration harness");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("connect database");
        let fixture = seed_fixture(&pool).await;
        let address = start_receiver(pool.clone()).await;

        // The generated Rust client proves the actual generated service and
        // typed response boundary, not a parser-only test double.
        let generated_hmac = hmac(MESH_AUTHORIZATION_CALLER, MESH_AUTHORIZATION_METHOD);
        let generated = generated_client(
            address,
            forwarded_session(&fixture.session),
            generated_hmac.clone(),
        );
        let resolved = generated
            .resolve_mesh_authorization(ResolveMeshAuthorizationRequest {
                org_id: fixture.org_id.clone(),
                ..Default::default()
            })
            .await
            .expect("session must resolve through generated service");
        let context = resolved.view().context.as_option().expect("typed context");
        assert_eq!(context.principal_id, fixture.user_id);
        assert_eq!(context.org_id, fixture.org_id);
        assert_eq!(
            context.credential_kind,
            MeshAuthorizationCredentialKind::SessionCookie
        );
        let generated_debug = format!("{resolved:?}");
        assert!(!generated_debug.contains(&fixture.session));
        assert!(!generated_debug.contains(&generated_hmac));

        let client = reqwest::Client::new();
        for (label, credential, expected_kind) in [
            (
                "OAuth bearer",
                format!("Bearer {}", fixture.oauth),
                "MESH_AUTHORIZATION_CREDENTIAL_KIND_OAUTH_BEARER",
            ),
            (
                "exact-org API key",
                format!("Bearer {}", fixture.api_key),
                "MESH_AUTHORIZATION_CREDENTIAL_KIND_API_KEY",
            ),
        ] {
            let response = post_receiver(
                &client,
                address,
                &fixture.org_id,
                MESH_FORWARDED_AUTHORIZATION_METADATA,
                &credential,
                &hmac(MESH_AUTHORIZATION_CALLER, MESH_AUTHORIZATION_METHOD),
            )
            .await;
            assert_eq!(response.status(), reqwest::StatusCode::OK, "{label}");
            let body = response.text().await.expect("response body");
            assert!(
                !body.contains(&credential),
                "{label}: forwarded credential appeared in the response"
            );
            let body: serde_json::Value = serde_json::from_str(&body).expect("response JSON");
            assert_eq!(body["context"]["principalId"], fixture.user_id);
            assert_eq!(body["context"]["credentialKind"], expected_kind);
        }

        let active_environment = post_receiver(
            &client,
            address,
            &fixture.org_id,
            MESH_FORWARDED_AUTHORIZATION_METADATA,
            &format!("Bearer {}", fixture.environment_token),
            &hmac(MESH_AUTHORIZATION_CALLER, MESH_AUTHORIZATION_METHOD),
        )
        .await;
        assert_eq!(active_environment.status(), reqwest::StatusCode::OK);
        let active_body = active_environment.text().await.expect("response body");
        assert!(
            !active_body.contains(&fixture.environment_token),
            "environment token appeared in the response"
        );
        let active_body: serde_json::Value =
            serde_json::from_str(&active_body).expect("response JSON");
        assert_eq!(
            active_body["context"]["principalKind"],
            "MESH_AUTHORIZATION_PRINCIPAL_KIND_ENVIRONMENT"
        );
        assert_eq!(
            active_body["context"]["credentialKind"],
            "MESH_AUTHORIZATION_CREDENTIAL_KIND_ENVIRONMENT_TOKEN"
        );

        for (label, credential, expected_status, expected_code) in [
            (
                "identity-only OAuth",
                format!("Bearer {}", fixture.identity_oauth),
                reqwest::StatusCode::FORBIDDEN,
                "permission_denied",
            ),
            (
                "expired OAuth",
                format!("Bearer {}", fixture.expired_oauth),
                reqwest::StatusCode::UNAUTHORIZED,
                "unauthenticated",
            ),
            (
                "revoked API key",
                format!("Bearer {}", fixture.revoked_api_key),
                reqwest::StatusCode::UNAUTHORIZED,
                "unauthenticated",
            ),
            (
                "destroying environment",
                format!("Bearer {}", fixture.destroying_environment_token),
                reqwest::StatusCode::UNAUTHORIZED,
                "unauthenticated",
            ),
        ] {
            let response = post_receiver(
                &client,
                address,
                &fixture.org_id,
                MESH_FORWARDED_AUTHORIZATION_METADATA,
                &credential,
                &hmac(MESH_AUTHORIZATION_CALLER, MESH_AUTHORIZATION_METHOD),
            )
            .await;
            assert_connect_error(response, expected_status, expected_code, label).await;
        }

        // The key's owner belongs to both organizations, but its credential
        // is still confined to its exact bound organization.
        let cross_org = post_receiver(
            &client,
            address,
            &fixture.other_org_id,
            MESH_FORWARDED_AUTHORIZATION_METADATA,
            &format!("Bearer {}", fixture.api_key),
            &hmac(MESH_AUTHORIZATION_CALLER, MESH_AUTHORIZATION_METHOD),
        )
        .await;
        assert_connect_error(
            cross_org,
            reqwest::StatusCode::FORBIDDEN,
            "permission_denied",
            "API key must not cross organizations",
        )
        .await;

        let missing_membership = post_receiver(
            &client,
            address,
            &fixture.unrelated_org_id,
            MESH_FORWARDED_AUTHORIZATION_METADATA,
            &format!("Bearer {}", fixture.oauth),
            &hmac(MESH_AUTHORIZATION_CALLER, MESH_AUTHORIZATION_METHOD),
        )
        .await;
        assert_connect_error(
            missing_membership,
            reqwest::StatusCode::FORBIDDEN,
            "permission_denied",
            "OAuth caller without organization membership",
        )
        .await;

        for (label, service, method) in [
            (
                "wrong HMAC service",
                "other-service",
                MESH_AUTHORIZATION_METHOD,
            ),
            (
                "wrong HMAC method",
                MESH_AUTHORIZATION_CALLER,
                "codewire.internal.v1.MeshAuthorizationService/OtherMethod",
            ),
        ] {
            let response = post_receiver(
                &client,
                address,
                &fixture.org_id,
                MESH_FORWARDED_SESSION_METADATA,
                &fixture.session,
                &hmac(service, method),
            )
            .await;
            assert_connect_error(
                response,
                reqwest::StatusCode::UNAUTHORIZED,
                "unauthenticated",
                label,
            )
            .await;
        }

        let mut tampered_hmac = hmac(MESH_AUTHORIZATION_CALLER, MESH_AUTHORIZATION_METHOD);
        tampered_hmac.push('x');
        let tampered_hmac_response = post_receiver(
            &client,
            address,
            &fixture.org_id,
            MESH_FORWARDED_SESSION_METADATA,
            &fixture.session,
            &tampered_hmac,
        )
        .await;
        assert_connect_error(
            tampered_hmac_response,
            reqwest::StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "tampered HMAC",
        )
        .await;

        assert_metadata_rejections(&client, address, &fixture).await;
    }

    async fn start_receiver(pool: PgPool) -> SocketAddr {
        let router = router(pool.clone());
        let app = AppBuilder::new("codewire-mesh-authorization-contract-test")
            .with_unary_connect_routes_mesh_authorization(
                router,
                MeshAuthorizationLayer::new(
                    AuthState { pool },
                    HMAC_SECRET,
                    MESH_AUTHORIZATION_CALLER,
                    MESH_AUTHORIZATION_METHOD,
                ),
            )
            .into_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind receiver");
        let address = listener.local_addr().expect("receiver address");
        tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
        address
    }

    fn generated_client(
        address: SocketAddr,
        forwarded_session: String,
        hmac: String,
    ) -> MeshAuthorizationServiceClient<HttpClient> {
        let config = ClientConfig::new(format!("http://{address}").parse().expect("receiver URI"))
            .with_codec_format(CodecFormat::Json)
            .with_default_header(AUTHORIZATION, format!("Bearer {hmac}"))
            .with_default_header(MESH_FORWARDED_SESSION_METADATA, forwarded_session);
        MeshAuthorizationServiceClient::new(HttpClient::plaintext_http2_only(), config)
    }

    async fn post_receiver(
        client: &reqwest::Client,
        address: SocketAddr,
        org_id: &str,
        lane: &str,
        raw_credential: &str,
        hmac: &str,
    ) -> reqwest::Response {
        client
            .post(format!("http://{address}/{MESH_AUTHORIZATION_METHOD}"))
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {hmac}"))
            .header(lane, standard_base64(raw_credential))
            .json(&serde_json::json!({ "orgId": org_id }))
            .send()
            .await
            .expect("private authorization request")
    }

    async fn assert_metadata_rejections(
        client: &reqwest::Client,
        address: SocketAddr,
        fixture: &Fixture,
    ) {
        let endpoint = format!("http://{address}/{MESH_AUTHORIZATION_METHOD}");
        let request_body = serde_json::json!({ "orgId": fixture.org_id });
        let valid_hmac = hmac(MESH_AUTHORIZATION_CALLER, MESH_AUTHORIZATION_METHOD);
        let session_wire = standard_base64(&fixture.session);
        let authorization_wire = standard_base64(&format!("Bearer {}", fixture.oauth));
        let sensitive = [
            fixture.session.as_str(),
            fixture.oauth.as_str(),
            valid_hmac.as_str(),
            session_wire.as_str(),
            authorization_wire.as_str(),
        ];

        let missing = client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {valid_hmac}"))
            .json(&request_body)
            .send()
            .await
            .expect("missing metadata request");
        assert_connect_error_redacted(
            missing,
            reqwest::StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "missing forwarded metadata",
            &sensitive,
        )
        .await;

        let malformed = client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {valid_hmac}"))
            .header(MESH_FORWARDED_SESSION_METADATA, "not=unpadded-base64")
            .json(&request_body)
            .send()
            .await
            .expect("malformed metadata request");
        assert_connect_error_redacted(
            malformed,
            reqwest::StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "malformed forwarded metadata",
            &sensitive,
        )
        .await;

        let mut duplicate_headers = HeaderMap::new();
        duplicate_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        duplicate_headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {valid_hmac}")).expect("HMAC header"),
        );
        let session_metadata = HeaderName::from_static(MESH_FORWARDED_SESSION_METADATA);
        duplicate_headers.append(
            session_metadata.clone(),
            HeaderValue::from_str(&session_wire).expect("session metadata"),
        );
        duplicate_headers.append(
            session_metadata,
            HeaderValue::from_str(&session_wire).expect("session metadata"),
        );
        let duplicate = client
            .post(&endpoint)
            .headers(duplicate_headers)
            .json(&request_body)
            .send()
            .await
            .expect("duplicate metadata request");
        assert_connect_error_redacted(
            duplicate,
            reqwest::StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "duplicate forwarded metadata",
            &sensitive,
        )
        .await;

        let ambiguous = client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {valid_hmac}"))
            .header(MESH_FORWARDED_SESSION_METADATA, &session_wire)
            .header(MESH_FORWARDED_AUTHORIZATION_METADATA, &authorization_wire)
            .json(&request_body)
            .send()
            .await
            .expect("ambiguous metadata request");
        assert_connect_error_redacted(
            ambiguous,
            reqwest::StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "ambiguous forwarded metadata",
            &sensitive,
        )
        .await;

        let raw_cookie = client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {valid_hmac}"))
            .header(MESH_FORWARDED_SESSION_METADATA, &session_wire)
            .header(
                "cookie",
                format!("codewire.session_token={}", fixture.session),
            )
            .json(&request_body)
            .send()
            .await
            .expect("raw cookie request");
        assert_connect_error_redacted(
            raw_cookie,
            reqwest::StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "raw cookie is not a forwarded lane",
            &sensitive,
        )
        .await;
    }

    async fn assert_connect_error(
        response: reqwest::Response,
        expected_status: reqwest::StatusCode,
        expected_code: &str,
        label: &str,
    ) {
        assert_eq!(response.status(), expected_status, "{label}");
        let body: serde_json::Value = response.json().await.expect("Connect error JSON");
        assert_eq!(body["code"], expected_code, "{label}: {body}");
    }

    async fn assert_connect_error_redacted(
        response: reqwest::Response,
        expected_status: reqwest::StatusCode,
        expected_code: &str,
        label: &str,
        sensitive: &[&str],
    ) {
        assert_eq!(response.status(), expected_status, "{label}");
        let body = response.text().await.expect("Connect error body");
        for raw in sensitive {
            assert!(
                !body.contains(raw),
                "{label}: private credential material appeared in the response"
            );
        }
        let body: serde_json::Value = serde_json::from_str(&body).expect("Connect error JSON");
        assert_eq!(body["code"], expected_code, "{label}: {body}");
    }

    fn hmac(service: &str, method: &str) -> String {
        issue_internal_hmac_token(HMAC_SECRET, service, method, Utc::now()).expect("issue HMAC")
    }

    fn standard_base64(value: &str) -> String {
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(value)
    }

    fn forwarded_session(session: &str) -> String {
        standard_base64(session)
    }

    async fn seed_fixture(pool: &PgPool) -> Fixture {
        let suffix = format!("{:x}", uuid::Uuid::new_v4());
        let slug_suffix = suffix.split('-').next().expect("UUID has a first segment");
        let user_id = format!("mesh-auth-user-{suffix}");
        let org_id = format!("mesh-auth-org-{suffix}");
        let other_org_id = format!("mesh-auth-other-org-{suffix}");
        let unrelated_org_id = format!("mesh-auth-unrelated-org-{suffix}");
        let client_id = format!("mesh-auth-client-{suffix}");
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(pool)
            .await
            .expect("seed user");
        for (org, slug, member) in [
            (&org_id, "mesh-auth", true),
            (&other_org_id, "mesh-auth-other", true),
            (&unrelated_org_id, "mesh-auth-unrelated", false),
        ] {
            sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
            )
            .bind(org)
            .bind(format!("{org} name"))
            .bind(format!("{slug}-{slug_suffix}"))
            .bind(&user_id)
            .execute(pool)
            .await
            .expect("seed organization");
            if member {
                sqlx::query(
                    "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'admin')",
                )
                .bind(format!("member-{org}"))
                .bind(org)
                .bind(&user_id)
                .execute(pool)
                .await
                .expect("seed membership");
            }
        }

        let session = format!("mesh-auth-session-{suffix}");
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, NOW() + interval '1 hour')",
        )
        .bind(format!("session-{suffix}"))
        .bind(&user_id)
        .bind(hash_session_token(&session))
        .execute(pool)
        .await
        .expect("seed session");

        let api_key = insert_api_key(pool, &user_id, &org_id, &suffix, false).await;
        let revoked_api_key =
            insert_api_key(pool, &user_id, &org_id, &format!("revoked-{suffix}"), true).await;

        sqlx::query(
            "INSERT INTO oidc_clients (id, name, application_type, auth_method, redirect_uris) VALUES ($1, $2, 'native', 'none', ARRAY['http://localhost:9878/callback'])",
        )
        .bind(&client_id)
        .bind(format!("Mesh authorization {suffix}"))
        .execute(pool)
        .await
        .expect("seed OIDC client");
        let oauth = format!("mesh-auth-oauth-{suffix}");
        let identity_oauth = format!("mesh-auth-identity-{suffix}");
        let expired_oauth = format!("mesh-auth-expired-{suffix}");
        for (token, scopes, interval) in [
            (&oauth, vec!["openid", "codewire.api"], "1 hour"),
            (&identity_oauth, vec!["openid"], "1 hour"),
            (&expired_oauth, vec!["openid", "codewire.api"], "-1 minute"),
        ] {
            sqlx::query(&format!(
                "INSERT INTO oidc_access_tokens (token_hash, client_id, user_id, scopes, expires_at) VALUES ($1, $2, $3, $4, NOW() + interval '{interval}')"
            ))
            .bind(hash_oauth_token(token))
            .bind(&client_id)
            .bind(&user_id)
            .bind(scopes)
            .execute(pool)
            .await
            .expect("seed OAuth token");
        }

        let environment_token =
            insert_environment(pool, &user_id, &org_id, &suffix, "running").await;
        let destroying_environment_token = insert_environment(
            pool,
            &user_id,
            &org_id,
            &format!("destroying-{suffix}"),
            "destroying",
        )
        .await;
        Fixture {
            user_id,
            org_id,
            other_org_id,
            unrelated_org_id,
            session,
            api_key,
            revoked_api_key,
            oauth,
            identity_oauth,
            expired_oauth,
            environment_token,
            destroying_environment_token,
        }
    }

    async fn insert_api_key(
        pool: &PgPool,
        user_id: &str,
        org_id: &str,
        suffix: &str,
        revoked: bool,
    ) -> String {
        let key = generate_api_key();
        sqlx::query(
            "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix, disabled_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(format!("key-{suffix}"))
        .bind(user_id)
        .bind(org_id)
        .bind(format!("Mesh authorization {suffix}"))
        .bind(hash_api_key(&key))
        .bind(api_key_prefix(&key))
        .bind(revoked.then(chrono::Utc::now))
        .execute(pool)
        .await
        .expect("seed API key");
        key
    }

    async fn insert_environment(
        pool: &PgPool,
        user_id: &str,
        org_id: &str,
        suffix: &str,
        state: &str,
    ) -> String {
        let preset_id = format!("mesh-auth-preset-{suffix}");
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug) VALUES ($1, $2, $3, $4)",
        )
        .bind(&preset_id)
        .bind(org_id)
        .bind(format!("Mesh authorization {suffix}"))
        .bind(&preset_id)
        .execute(pool)
        .await
        .expect("seed environment preset");
        let environment_id = format!("mesh-auth-environment-id-{suffix}");
        let token = format!("mesh-auth-environment-token-{suffix}");
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, state, desired_state, preset_id, auth_token) VALUES ($1, $2, $3, 'sandbox', $4, 'started', $5, $6)",
        )
        .bind(environment_id)
        .bind(org_id)
        .bind(user_id)
        .bind(state)
        .bind(&preset_id)
        .bind(&token)
        .execute(pool)
        .await
        .expect("seed environment");
        token
    }

    #[test]
    fn stored_roles_map_only_to_the_published_proto_enum() {
        assert_eq!(proto_role("owner").expect("owner"), OrgRole::Owner);
        assert_eq!(proto_role("admin").expect("admin"), OrgRole::Admin);
        assert_eq!(proto_role("member").expect("member"), OrgRole::Member);
        assert!(matches!(
            proto_role("unexpected"),
            Err(AppError::InternalMsg(_))
        ));
    }
}
