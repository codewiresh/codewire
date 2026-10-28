//! Real handlers and standard SQLx schema, using only disposable synthetic identities.
use super::*;
use anyhow::{Context, Result};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

const FRONTEND: &str = "https://dashboard.example.test";
const HOST: &str = "app-abcde-preview-org.preview.test";
const ACCOUNT_TOKEN: &str = "synthetic-preview-account-cookie-never-send-to-preview";
const SECRET: &str = "synthetic-preview-signing-secret-no-external-authority";

struct Fixture {
    admin: PgPool,
    name: String,
    pool: PgPool,
}

impl Fixture {
    async fn create(connections: u32) -> Result<Self> {
        let admin_url =
            std::env::var("TEST_DATABASE_URL").context("disposable TEST_DATABASE_URL required")?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await?;
        let name = format!("cw_preview_auth_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await?;
        let mut url = url::Url::parse(&admin_url)?;
        url.set_path(&name);
        codewire_server_core::migrate::ensure_schema(url.as_str()).await?;
        // The acquire timeout is a hang guard, not a bound under test: a
        // handler that waited on itself for its last connection still fails
        // when it ends, but opening a connection on a loaded database host
        // may take longer than a few seconds. With 3 s, the ten database
        // lanes at once failed a fixture query here ("pool timed out").
        let pool = PgPoolOptions::new()
            .max_connections(connections)
            .acquire_timeout(Duration::from_secs(60))
            .connect(url.as_str())
            .await?;
        let fixture = Self { admin, name, pool };
        let seeded = fixture.seed().await;
        if let Err(error) = seeded {
            fixture.cleanup().await?;
            return Err(error);
        }
        Ok(fixture)
    }

    async fn seed(&self) -> Result<()> {
        sqlx::raw_sql("INSERT INTO users(id,email,enabled) VALUES('preview-user','preview@example.test',true),('other-user','other@example.test',true); \
            INSERT INTO organizations(id,name,slug,created_by) VALUES('preview-org','Preview','preview-org','preview-user'); \
            INSERT INTO org_members(id,org_id,user_id,role) VALUES('preview-member','preview-org','preview-user','owner'),('other-member','preview-org','other-user','viewer'); \
            INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES('preview-preset','preview-org','Preview','preview','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
            INSERT INTO environments(id,org_id,created_by,type,name,preset_id,state,desired_state,project_spec) VALUES('abcde-preview-env','preview-org','preview-user','sandbox','Preview sandbox','preview-preset','running','started','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
            INSERT INTO sandbox_environment_backend(environment_id,namespace,pod_ip,setup_complete) VALUES('abcde-preview-env','synthetic-preview','127.0.0.1',true); \
            INSERT INTO environment_ports(id,environment_id,port,label,access) VALUES('preview-port','abcde-preview-env',3000,'app','creator'),('other-port','abcde-preview-env',3001,'other','creator');")
            .execute(&self.pool).await?;
        sqlx::query("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES('preview-session','preview-user',$1,clock_timestamp()+interval '1 hour'),('other-session','other-user',$2,clock_timestamp()+interval '1 hour')")
            .bind(hash_session_token(ACCOUNT_TOKEN)).bind(hash_session_token("other-synthetic-cookie")).execute(&self.pool).await?;
        Ok(())
    }

    fn context(&self) -> PreviewContext<'_> {
        PreviewContext {
            pool: &self.pool,
            preview_base_domain: "preview.test",
            frontend_url: FRONTEND,
            session_secret: SECRET,
            confidential_storage_flags: crate::confidential_storage::FeatureFlags {
                enabled: false,
            },
            // Tests must observe database writes immediately, so the
            // context carries a zero-TTL cache: every lookup is one query,
            // the pre-L5 behavior.
            org_slugs: zero_ttl_org_slugs(),
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.pool.close().await;
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        Ok(())
    }

    async fn target(&self) -> Result<(PreviewHostMatch, PreviewTarget)> {
        let matched = super::super::resolve_preview_host(&self.pool, "preview.test", HOST)
            .await
            .map_err(|_| anyhow::anyhow!("synthetic preview host not resolved"))?
            .context("preview match missing")?;
        let target = accepted(super::super::resolve_preview_target(&self.pool, &matched).await)?;
        Ok((matched, target))
    }

    async fn counts(&self) -> Result<(i64, i64)> {
        Ok(sqlx::query_as("SELECT (SELECT count(*) FROM preview_auth_challenges),(SELECT count(*) FROM preview_browser_grants)").fetch_one(&self.pool).await?)
    }

    /// Returns the continuation and this sign-in's nonce cookie pair.
    async fn begin(&self) -> Result<(String, String)> {
        let (matched, target) = self.target().await?;
        let response = accepted(
            start(
                &self.context(),
                &matched,
                &target,
                HOST,
                "/nested?filter=synthetic",
            )
            .await,
        )?;
        anyhow::ensure!(response.status() == StatusCode::SEE_OTHER);
        assert_private(&response);
        let nonce = nonce_pair(&response)?;
        let destination = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
        anyhow::ensure!(
            destination.origin().ascii_serialization() == FRONTEND
                && destination.path() == AUTHORIZE_PATH
        );
        let continuation = destination
            .query_pairs()
            .find(|(k, _)| k == "challenge")
            .context("missing continuation")?
            .1
            .into_owned();
        Ok((continuation, nonce))
    }

    async fn approve(&self, continuation: &str) -> Result<String> {
        let confirmation = html(accepted(
            authorize_page_inner(&self.context(), &account_headers(), continuation).await,
        )?)
        .await?;
        let csrf = field(&confirmation, "csrf")?;
        let response = accepted(
            authorize_inner(
                &self.context(),
                &account_headers(),
                Approval {
                    challenge: continuation.into(),
                    csrf,
                },
            )
            .await,
        )?;
        anyhow::ensure!(
            response.status() == StatusCode::OK
                && !response.headers().contains_key(header::LOCATION)
        );
        assert_private(&response);
        let html = html(response).await?;
        anyhow::ensure!(html.contains(&format!("https://{HOST}{CALLBACK_PATH}")));
        field(&html, "code")
    }

    async fn finish(&self, code: &str, nonce: &str) -> Result<String> {
        let response =
            accepted(callback(&self.context(), callback_request(code, nonce), HOST).await)?;
        anyhow::ensure!(
            response.status() == StatusCode::SEE_OTHER
                && response.headers()[header::LOCATION] == "/nested?filter=synthetic"
        );
        assert_private(&response);
        response_cookie(&response, GRANT_COOKIE)
    }

    /// The proxy's own steps for a GET that carries the grant cookie `token`:
    /// its grant lookup, then its access decision.
    async fn proxied_with_grant(&self, token: &str) -> Result<StatusCode> {
        let (matched, target) = self.target().await?;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, format!("{GRANT_COOKIE}={token}").parse()?);
        let user = accepted(grant_user(&self.context(), &headers, HOST, &matched, &target).await)?;
        let Some(user) = user else {
            return Ok(StatusCode::UNAUTHORIZED);
        };
        self.proxied_as(&user, &headers).await
    }

    /// The proxy's access decision for a request authenticated as `user`.
    async fn proxied_as(&self, user: &AuthUser, headers: &HeaderMap) -> Result<StatusCode> {
        let (matched, target) = self.target().await?;
        let decision = authorize_proxy_user(
            &self.context(),
            &Method::GET,
            headers,
            user,
            &matched,
            &target,
        )
        .await;
        Ok(decision.map_or_else(|response| response.status(), |()| StatusCode::OK))
    }

    async fn granted(&self, token: &str) -> Result<bool> {
        let (matched, target) = self.target().await?;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, format!("{GRANT_COOKIE}={token}").parse()?);
        let user = accepted(grant_user(&self.context(), &headers, HOST, &matched, &target).await)?;
        Ok(match user {
            Some(user) => check_access(&self.context(), &user, &matched, &target)
                .await
                .is_ok(),
            None => false,
        })
    }
}

/// A handler's success, or an error naming the step that was refused (#2315).
#[track_caller]
fn accepted<T>(result: std::result::Result<T, Response>) -> Result<T> {
    let step = std::panic::Location::caller();
    result.map_err(|response| {
        anyhow::anyhow!(
            "handler rejected synthetic request at {step}: {}",
            response.status()
        )
    })
}

fn rejected<T>(result: std::result::Result<T, Response>, expected: StatusCode) -> Result<()> {
    match result {
        Err(response) => anyhow::ensure!(
            response.status() == expected,
            "expected {expected}, got {}",
            response.status()
        ),
        Ok(_) => anyhow::bail!("invalid synthetic request accepted"),
    }
    Ok(())
}

fn assert_private(response: &Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    // Auto-submitting pages disclose only their origin so the next POST's
    // exact Origin check passes; nothing private ever discloses a path.
    let policy = response.headers()[header::REFERRER_POLICY]
        .to_str()
        .unwrap();
    assert!(
        ["no-referrer", "strict-origin"].contains(&policy),
        "{policy}"
    );
}

async fn html(response: Response) -> Result<String> {
    Ok(String::from_utf8(
        to_bytes(response.into_body(), 32 * 1024).await?.to_vec(),
    )?)
}

fn field(html: &str, name: &str) -> Result<String> {
    Ok(html
        .split_once(&format!("name=\"{name}\" value=\""))
        .context("expected native hidden input")?
        .1
        .split_once('"')
        .context("unterminated input")?
        .0
        .into())
}

/// The fresh nonce cookie a start response sets, as a `name=value` pair.
fn nonce_pair(response: &Response) -> Result<String> {
    let header = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{NONCE_COOKIE}-")))
        .context("missing nonce cookie")?;
    anyhow::ensure!(
        header.contains("Path=/")
            && header.contains("Secure; HttpOnly")
            && !header.contains("Domain=")
    );
    Ok(header.split(';').next().unwrap().into())
}

fn response_cookie(response: &Response, name: &str) -> Result<String> {
    let header = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .context("missing scoped cookie")?;
    anyhow::ensure!(
        header.contains("Path=/")
            && header.contains("Secure; HttpOnly")
            && !header.contains("Domain=")
    );
    Ok(header
        .split_once('=')
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap()
        .into())
}

fn account_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "dashboard.example.test".parse().unwrap());
    headers.insert(header::ORIGIN, FRONTEND.parse().unwrap());
    headers.insert(
        header::COOKIE,
        format!("{SESSION_COOKIE_NAME}={ACCOUNT_TOKEN}")
            .parse()
            .unwrap(),
    );
    headers
}

/// The challenge a nonce cookie pair belongs to, and its value.
fn nonce_parts(nonce: &str) -> (&str, &str) {
    let (name, value) = nonce.split_once('=').unwrap();
    (
        name.strip_prefix(&format!("{NONCE_COOKIE}-")).unwrap(),
        value,
    )
}

fn callback_request(code: &str, nonce: &str) -> Request<Body> {
    let (challenge, _) = nonce_parts(nonce);
    Request::builder()
        .method(Method::POST)
        .uri(CALLBACK_PATH)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, FRONTEND)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, nonce)
        .body(Body::from(format!("code={code}&challenge={challenge}")))
        .unwrap()
}

/// The real answer of a callback that ran beside another for the same
/// account, taken once both have finished. The two take turns on the
/// account's lock, and one that waits longer than its transaction's lock
/// timeout, or for a database connection, is refused with 503 and consumes
/// nothing. Under load that is a correct outcome (#2315). Once the other
/// callback has finished nothing contends for the lock, so one retry, as a
/// browser would make, answers. A second refusal fails the test.
#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn after_contention(
    answer: std::result::Result<Response, Response>,
    context: &PreviewContext<'_>,
    code: &str,
    nonce: &str,
) -> std::result::Result<Response, Response> {
    match answer {
        Err(refused) if refused.status() == StatusCode::SERVICE_UNAVAILABLE => {
            callback(context, callback_request(code, nonce), HOST).await
        }
        answer => answer,
    }
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn single_connection_roundtrip_is_stateless_until_confirmation_and_replay_fenced()
-> Result<()> {
    let f = Fixture::create(1).await?;
    // No wall-clock budget (#2315): under load these steps can outlast any
    // fixed one. A handler that waited on itself for the one connection
    // would be refused when the pool's acquire timeout ends, which fails
    // the test.
    let result = async {
        for _ in 0..12 { f.begin().await?; }
        let (continuation, nonce) = f.begin().await?;
        anyhow::ensure!(f.counts().await? == (0, 0));
        let mut anonymous = account_headers(); anonymous.remove(header::COOKIE);
        let login = accepted(authorize_page_inner(&f.context(), &anonymous, &continuation).await)?;
        anyhow::ensure!(login.status() == StatusCode::SEE_OTHER && login.headers()[header::LOCATION].to_str()?.starts_with(&format!("{FRONTEND}/login?return_to=")));
        anyhow::ensure!(f.counts().await? == (0, 0));
        let expiry: chrono::NaiveDateTime = sqlx::query_scalar("SELECT expires_at FROM sessions WHERE id='preview-session'").fetch_one(&f.pool).await?;
        let code = f.approve(&continuation).await?;
        anyhow::ensure!(f.counts().await? == (1, 0));
        let token = f.finish(&code, &nonce).await?;
        anyhow::ensure!(f.granted(&token).await? && f.counts().await? == (1, 1));
        let stored: (String, String, bool) = sqlx::query_as("SELECT c.nonce_hash,c.code_hash,c.consumed_at IS NOT NULL FROM preview_auth_challenges c").fetch_one(&f.pool).await?;
        anyhow::ensure!(stored == (token_hash(nonce_parts(&nonce).1), token_hash(&code), true));
        anyhow::ensure!(sqlx::query_scalar::<_, String>("SELECT token_hash FROM preview_browser_grants").fetch_one(&f.pool).await? == token_hash(&token));
        let serialized: String = sqlx::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(c) FROM preview_auth_challenges c),(SELECT jsonb_agg(g) FROM preview_browser_grants g))::text").fetch_one(&f.pool).await?;
        for raw in [nonce_parts(&nonce).1, code.as_str(), token.as_str(), ACCOUNT_TOKEN] { anyhow::ensure!(!serialized.contains(raw)); }
        anyhow::ensure!(sqlx::query_scalar::<_, chrono::NaiveDateTime>("SELECT expires_at FROM sessions WHERE id='preview-session'").fetch_one(&f.pool).await? == expiry);
        rejected(callback(&f.context(), callback_request(&code, &nonce), HOST).await, StatusCode::BAD_REQUEST)?;
        let decoded = decode_start(&f.context(), &continuation).map_err(|_| anyhow::anyhow!("continuation decode"))?;
        rejected(authorize_inner(&f.context(), &account_headers(), Approval { challenge: continuation, csrf: confirmation_token(SECRET, "preview-session", &decoded.challenge.id) }).await, StatusCode::BAD_REQUEST)?;
        anyhow::ensure!(f.counts().await? == (1, 1));
        Ok(())
    }.await;
    result.and(f.cleanup().await)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn confirmation_rejects_tamper_expiry_wrong_host_origin_csrf_and_session_confusion()
-> Result<()> {
    let f = Fixture::create(2).await?;
    let result = async {
        let (continuation, _) = f.begin().await?;
        let decoded =
            decode_start(&f.context(), &continuation).map_err(|_| anyhow::anyhow!("decode"))?;
        let csrf = confirmation_token(SECRET, "preview-session", &decoded.challenge.id);
        let mut expired =
            decode_start(&f.context(), &continuation).map_err(|_| anyhow::anyhow!("decode"))?;
        expired.expires_at = chrono::Utc::now().timestamp() - 1;
        let expired = seal_start(SECRET, &expired).map_err(|_| anyhow::anyhow!("seal"))?;
        for token in [format!("x{continuation}"), expired] {
            rejected(
                authorize_page_inner(&f.context(), &account_headers(), &token).await,
                StatusCode::BAD_REQUEST,
            )?;
        }
        for (header_name, value) in [
            (header::HOST, "wrong.example.test"),
            (header::ORIGIN, "https://wrong.example.test"),
        ] {
            let mut headers = account_headers();
            headers.insert(header_name, value.parse()?);
            rejected(
                authorize_inner(
                    &f.context(),
                    &headers,
                    Approval {
                        challenge: continuation.clone(),
                        csrf: csrf.clone(),
                    },
                )
                .await,
                StatusCode::BAD_REQUEST,
            )?;
        }
        let mut duplicate = account_headers();
        duplicate.append(header::ORIGIN, FRONTEND.parse()?);
        rejected(
            authorize_inner(
                &f.context(),
                &duplicate,
                Approval {
                    challenge: continuation.clone(),
                    csrf: csrf.clone(),
                },
            )
            .await,
            StatusCode::BAD_REQUEST,
        )?;
        rejected(
            authorize_inner(
                &f.context(),
                &account_headers(),
                Approval {
                    challenge: continuation.clone(),
                    csrf: "wrong".into(),
                },
            )
            .await,
            StatusCode::FORBIDDEN,
        )?;
        let mut duplicate = account_headers();
        duplicate.append(
            header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={ACCOUNT_TOKEN}").parse()?,
        );
        rejected(
            authorize_page_inner(&f.context(), &duplicate, &continuation).await,
            StatusCode::BAD_REQUEST,
        )?;
        let mut bearer = account_headers();
        bearer.insert(header::AUTHORIZATION, "Bearer synthetic".parse()?);
        rejected(
            authorize_page_inner(&f.context(), &bearer, &continuation).await,
            StatusCode::BAD_REQUEST,
        )?;
        let mut other = account_headers();
        other.insert(
            header::COOKIE,
            format!("{SESSION_COOKIE_NAME}=other-synthetic-cookie").parse()?,
        );
        rejected(
            authorize_inner(
                &f.context(),
                &other,
                Approval {
                    challenge: continuation,
                    csrf,
                },
            )
            .await,
            StatusCode::FORBIDDEN,
        )?;
        anyhow::ensure!(f.counts().await? == (0, 0));
        Ok(())
    }
    .await;
    result.and(f.cleanup().await)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn callback_rejects_wrong_transport_nonce_host_and_expiry_without_consumption() -> Result<()>
{
    let f = Fixture::create(2).await?;
    let result = async {
        let (continuation, nonce) = f.begin().await?;
        let code = f.approve(&continuation).await?;
        for case in 0..10 {
            let mut request = callback_request(&code, &nonce);
            match case {
                0 => *request.method_mut() = Method::GET,
                1 => { request.headers_mut().insert(header::ORIGIN, "https://attacker.example.test".parse()?); },
                2 => *request.uri_mut() = format!("{CALLBACK_PATH}?code=forbidden").parse()?,
                3 => { request.headers_mut().insert(header::CONTENT_TYPE, "text/plain".parse()?); },
                4 => { request.headers_mut().insert(header::COOKIE, format!("{NONCE_COOKIE}-{}={}", nonce_parts(&nonce).0, random_token().unwrap()).parse()?); },
                5 => { request.headers_mut().append(header::COOKIE, nonce.parse()?); },
                6 => *request.body_mut() = Body::from(format!("code={code}&code={code}")),
                7 => *request.body_mut() = Body::from(format!("code={code}&challenge={}&extra=field", nonce_parts(&nonce).0)),
                // Another sign-in's challenge cannot redeem this code.
                8 => *request.body_mut() = Body::from(format!("code={code}&challenge={}", uuid::Uuid::new_v4())),
                _ => { request.headers_mut().insert(header::COOKIE, format!("{NONCE_COOKIE}={}", nonce_parts(&nonce).1).parse()?); },
            }
            rejected(callback(&f.context(), request, HOST).await, StatusCode::BAD_REQUEST)?;
        }
        rejected(callback(&f.context(), callback_request(&code, &nonce), "other-abcde-preview-org.preview.test").await, StatusCode::BAD_REQUEST)?;
        sqlx::query("UPDATE preview_auth_challenges SET code_expires_at=clock_timestamp()-interval '1 second'").execute(&f.pool).await?;
        rejected(callback(&f.context(), callback_request(&code, &nonce), HOST).await, StatusCode::BAD_REQUEST)?;
        sqlx::query("UPDATE preview_auth_challenges SET code_expires_at=LEAST(expires_at,clock_timestamp()+interval '30 seconds')").execute(&f.pool).await?;
        anyhow::ensure!(f.counts().await? == (1, 0) && sqlx::query_scalar::<_, bool>("SELECT consumed_at IS NULL FROM preview_auth_challenges").fetch_one(&f.pool).await?);
        let token = f.finish(&code, &nonce).await?;
        anyhow::ensure!(f.granted(&token).await?);
        sqlx::query("UPDATE preview_browser_grants SET created_at=clock_timestamp()-interval '2 hours'").execute(&f.pool).await?;
        anyhow::ensure!(f.granted(&token).await?, "an old grant remains valid with its live parent session");
        Ok(())
    }.await;
    result.and(f.cleanup().await)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn concurrent_callbacks_consume_once_and_reissue_the_same_scoped_grant() -> Result<()> {
    let f = Fixture::create(4).await?;
    // No wall-clock budget: under load these steps can outlast any fixed one
    // (#2315). Every wait in the handlers is bounded by the transaction's
    // lock timeout or the pool's acquire timeout, so a callback stuck behind
    // the other is refused instead of hanging, and a refusal that a retry
    // does not clear fails the test.
    let result = async {
        let (continuation, nonce) = f.begin().await?;
        let code = f.approve(&continuation).await?;
        let context = f.context();
        let (a, b) = tokio::join!(
            callback(&context, callback_request(&code, &nonce), HOST),
            callback(&context, callback_request(&code, &nonce), HOST)
        );
        let a = after_contention(a, &context, &code, &nonce).await;
        let b = after_contention(b, &context, &code, &nonce).await;
        anyhow::ensure!(a.is_ok() != b.is_ok());
        rejected(if a.is_err() { a } else { b }, StatusCode::BAD_REQUEST)?;
        anyhow::ensure!(f.counts().await? == (1, 1));
        // Concurrent tabs each get a fresh nonce of their own; neither replaces
        // the other's, and both reach the same scoped grant.
        let (one, nonce_one) = f.begin().await?;
        let (two, nonce_two) = f.begin().await?;
        anyhow::ensure!(nonce_one != nonce && nonce_two != nonce && nonce_one != nonce_two);
        let first = f.approve(&one).await?;
        let second = f.approve(&two).await?;
        rejected(
            callback(&context, callback_request(&first, &nonce_two), HOST).await,
            StatusCode::BAD_REQUEST,
        )?;
        let (a, b) = tokio::join!(
            callback(&context, callback_request(&first, &nonce_one), HOST),
            callback(&context, callback_request(&second, &nonce_two), HOST)
        );
        // A refused callback consumed nothing: its retry still succeeds.
        let a = after_contention(a, &context, &first, &nonce_one).await;
        let b = after_contention(b, &context, &second, &nonce_two).await;
        let a = response_cookie(&accepted(a)?, GRANT_COOKIE)?;
        let b = response_cookie(&accepted(b)?, GRANT_COOKIE)?;
        anyhow::ensure!(
            a == b && f.granted(&b).await? && f.granted(&a).await? && f.counts().await? == (3, 1)
        );
        Ok(())
    }
    .await;
    result.and(f.cleanup().await)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn repeated_browser_reopening_reuses_one_grant_without_exhausting_scope_quota() -> Result<()>
{
    let f = Fixture::create(2).await?;
    let result = async {
        let mut first = None;
        for _ in 0..12 {
            let (continuation, nonce) = f.begin().await?;
            let code = f.approve(&continuation).await?;
            let token = f.finish(&code, &nonce).await?;
            anyhow::ensure!(f.granted(&token).await?);
            if let Some(previous) = &first {
                anyhow::ensure!(&token == previous);
            } else {
                first = Some(token);
            }
            // Move the short-lived handoff clock forward without sleeping;
            // production cleanup removes these rows after five minutes.
            sqlx::query("DELETE FROM preview_auth_challenges WHERE consumed_at IS NOT NULL")
                .execute(&f.pool)
                .await?;
        }
        anyhow::ensure!(f.counts().await? == (0, 1));
        Ok(())
    }
    .await;
    result.and(f.cleanup().await)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn logout_disable_expiry_and_cross_user_cleanup_do_not_leave_preview_authority() -> Result<()>
{
    for mutation in [
        "DELETE FROM sessions WHERE id='preview-session'",
        "UPDATE users SET enabled=false WHERE id='preview-user'",
        "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id='preview-session'",
    ] {
        for before_callback in [true, false] {
            let f = Fixture::create(2).await?;
            let result = async {
                let (continuation, nonce) = f.begin().await?;
                let code = f.approve(&continuation).await?;
                let token = if before_callback {
                    None
                } else {
                    Some(f.finish(&code, &nonce).await?)
                };
                sqlx::query(mutation).execute(&f.pool).await?;
                if let Some(token) = token {
                    anyhow::ensure!(!f.granted(&token).await?);
                } else {
                    anyhow::ensure!(
                        callback(&f.context(), callback_request(&code, &nonce), HOST)
                            .await
                            .is_err()
                    );
                }
                anyhow::ensure!(
                    authorize_page_inner(&f.context(), &account_headers(), &continuation)
                        .await
                        .is_ok_and(|r| r.status() == StatusCode::SEE_OTHER)
                );
                Ok(())
            }
            .await;
            result.and(f.cleanup().await)?;
        }
    }
    let f = Fixture::create(1).await?;
    let result = async {
        sqlx::raw_sql("UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id='other-session'; \
            INSERT INTO preview_auth_challenges(id,nonce_hash,client_hash,organization_id,environment_id,port_id,host,return_path,created_at,expires_at,session_id,code_hash,code_expires_at) VALUES('expired-other',repeat('a',64),repeat('b',64),'preview-org','abcde-preview-env','preview-port','app-abcde-preview-org.preview.test','/',clock_timestamp()-interval '6 minutes',clock_timestamp()-interval '2 minutes','other-session',repeat('c',64),clock_timestamp()-interval '3 minutes'); \
            INSERT INTO preview_browser_grants(token_hash,session_id,organization_id,environment_id,port_id,host,created_at) VALUES(repeat('d',64),'other-session','preview-org','abcde-preview-env','preview-port','app-abcde-preview-org.preview.test',clock_timestamp()-interval '2 hours');")
            .execute(&f.pool).await?;
        let (continuation, _) = f.begin().await?; f.approve(&continuation).await?;
        anyhow::ensure!(f.counts().await? == (1, 0));
        Ok(())
    }.await;
    result.and(f.cleanup().await)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn exact_port_host_and_current_audience_membership_are_revalidated() -> Result<()> {
    let f = Fixture::create(2).await?;
    let result = async {
        let (continuation, nonce) = f.begin().await?;
        let code = f.approve(&continuation).await?;
        let token = f.finish(&code, &nonce).await?;
        let (matched, mut target) = f.target().await?;
        let mut headers = HeaderMap::new(); headers.insert(header::COOKIE, format!("{GRANT_COOKIE}={token}").parse()?);
        anyhow::ensure!(accepted(grant_user(&f.context(), &headers, "other-abcde-preview-org.preview.test", &matched, &target).await)?.is_none());
        target.port_id = "other-port".into();
        anyhow::ensure!(accepted(grant_user(&f.context(), &headers, HOST, &matched, &target).await)?.is_none());
        let (_, target) = f.target().await?;
        // An account session cookie on a preview host was planted by another
        // preview; it neither authenticates nor blocks the grant.
        headers.append(header::COOKIE, format!("{SESSION_COOKIE_NAME}={ACCOUNT_TOKEN}").parse()?);
        anyhow::ensure!(accepted(grant_user(&f.context(), &headers, HOST, &matched, &target).await)?.is_some());
        sqlx::query("UPDATE environment_ports SET access='org_members' WHERE id='preview-port'").execute(&f.pool).await?;
        // Remove the creator shortcut so this assertion actually exercises
        // current organization-role authority, not creator access.
        sqlx::query("UPDATE environments SET created_by='other-user' WHERE id='abcde-preview-env'").execute(&f.pool).await?;
        anyhow::ensure!(f.granted(&token).await?);
        sqlx::query("DELETE FROM org_members WHERE id='preview-member'").execute(&f.pool).await?;
        anyhow::ensure!(!f.granted(&token).await?);
        sqlx::raw_sql("INSERT INTO org_members(id,org_id,user_id,role) VALUES('preview-member','preview-org','preview-user','viewer'); INSERT INTO environment_access(id,environment_id,user_id,permission,granted_by) VALUES('preview-access','abcde-preview-env','preview-user','viewer','other-user');").execute(&f.pool).await?;
        anyhow::ensure!(f.granted(&token).await?);
        sqlx::query("DELETE FROM environment_access WHERE id='preview-access'").execute(&f.pool).await?;
        anyhow::ensure!(!f.granted(&token).await?);
        sqlx::query("UPDATE environment_ports SET access='creator' WHERE id='preview-port'").execute(&f.pool).await?;
        sqlx::query("UPDATE environments SET created_by='preview-user' WHERE id='abcde-preview-env'").execute(&f.pool).await?;
        let (continuation, nonce) = f.begin().await?;
        let code = f.approve(&continuation).await?;
        sqlx::query("UPDATE environments SET created_by='other-user' WHERE id='abcde-preview-env'").execute(&f.pool).await?;
        rejected(callback(&f.context(), callback_request(&code, &nonce), HOST).await, StatusCode::FORBIDDEN)?;
        anyhow::ensure!(!f.granted(&token).await?);
        sqlx::raw_sql("DELETE FROM environment_ports WHERE id='preview-port'; INSERT INTO environment_ports(id,environment_id,port,label,access) VALUES('replacement-port','abcde-preview-env',3000,'app','creator');").execute(&f.pool).await?;
        anyhow::ensure!(!f.granted(&token).await?);
        rejected(callback(&f.context(), callback_request(&code, &nonce), HOST).await, StatusCode::BAD_REQUEST)?;
        // The existing environment and this shadow share org, first-five ID
        // prefix and port label. No ordering may select one arbitrarily.
        // The underscore fixture separately pins literal prefix matching;
        // this is a SQL lookup test, not permission for underscore DNS names.
        for id in ["abcde-shadow", "abcd_-literal"] {
            sqlx::query("INSERT INTO environments(id,org_id,created_by,type,name,preset_id,state,desired_state,project_spec) SELECT $1,org_id,created_by,type,name,preset_id,state,desired_state,project_spec FROM environments WHERE id='abcde-preview-env'")
                .bind(id).execute(&f.pool).await?;
            sqlx::query("INSERT INTO sandbox_environment_backend(environment_id,namespace,pod_ip,setup_complete) VALUES($1,'synthetic-preview','127.0.0.1',true)")
                .bind(id).execute(&f.pool).await?;
            sqlx::query("INSERT INTO environment_ports(id,environment_id,port,label,access) VALUES($1,$1,3000,'app','creator')")
                .bind(id).execute(&f.pool).await?;
        }
        rejected(super::super::resolve_preview_target(&f.pool, &matched).await, StatusCode::NOT_FOUND)?;
        let literal = PreviewHostMatch { org_id: matched.org_id.clone(), label: "app".into(), env_prefix: "abcd_".into() };
        let resolved = accepted(super::super::resolve_preview_target(&f.pool, &literal).await)?;
        anyhow::ensure!(resolved.env_id == "abcd_-literal" && resolved.port_id == "abcd_-literal");
        Ok(())
    }.await;
    result.and(f.cleanup().await)
}

// Removing a member deletes only their membership row. Their environment's
// creator column and any environment grant stay behind, so neither may keep
// the preview open (#3254).
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn removed_creator_loses_creator_and_member_preview_access() -> Result<()> {
    let f = Fixture::create(2).await?;
    let result = async {
        let (continuation, nonce) = f.begin().await?;
        let code = f.approve(&continuation).await?;
        let token = f.finish(&code, &nonce).await?;
        anyhow::ensure!(f.granted(&token).await?);
        sqlx::raw_sql("DELETE FROM org_members WHERE id='preview-member'; INSERT INTO environment_access(id,environment_id,user_id,permission,granted_by) VALUES('preview-access','abcde-preview-env','preview-user','viewer','other-user');").execute(&f.pool).await?;
        anyhow::ensure!(!f.granted(&token).await?, "creator access outlived the removal");
        sqlx::query("UPDATE environment_ports SET access='org_members' WHERE id='preview-port'").execute(&f.pool).await?;
        anyhow::ensure!(!f.granted(&token).await?, "an old grant outlived the removal");
        // A re-added viewer is a current member again: the grant and the
        // creator shortcut apply once more.
        sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES('preview-member','preview-org','preview-user','viewer')").execute(&f.pool).await?;
        anyhow::ensure!(f.granted(&token).await?);
        sqlx::query("UPDATE environment_ports SET access='creator' WHERE id='preview-port'").execute(&f.pool).await?;
        anyhow::ensure!(f.granted(&token).await?);
        Ok(())
    }.await;
    result.and(f.cleanup().await)
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL"]
async fn removed_creator_proxy_requests_are_refused_for_old_grants_and_bearers() -> Result<()> {
    // The proxy decides every request itself: a grant issued before the
    // creator's removal, and an organization-free Bearer credential such as
    // an OIDC access token, stop opening the creator port once the creator
    // is no longer a member (#3254).
    let f = Fixture::create(2).await?;
    let result = async {
        let (continuation, nonce) = f.begin().await?;
        let code = f.approve(&continuation).await?;
        let token = f.finish(&code, &nonce).await?;
        let bearer = |user_id: &str| AuthUser {
            user_id: user_id.to_string(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        };
        let no_cookie = HeaderMap::new();
        anyhow::ensure!(f.proxied_with_grant(&token).await? == StatusCode::OK);
        anyhow::ensure!(f.proxied_as(&bearer("preview-user"), &no_cookie).await? == StatusCode::OK);
        anyhow::ensure!(
            f.proxied_as(&bearer("other-user"), &no_cookie).await? == StatusCode::FORBIDDEN,
            "a member who did not create the environment opened its creator port"
        );

        sqlx::query("DELETE FROM org_members WHERE id = 'preview-member'")
            .execute(&f.pool)
            .await?;
        anyhow::ensure!(
            f.proxied_with_grant(&token).await? == StatusCode::FORBIDDEN,
            "a grant issued before the removal still opened the creator port"
        );
        anyhow::ensure!(
            f.proxied_as(&bearer("preview-user"), &no_cookie).await? == StatusCode::FORBIDDEN,
            "a removed creator's Bearer credential still opened the creator port"
        );

        // Re-added as a member, the creator reaches the port again.
        sqlx::query("INSERT INTO org_members(id,org_id,user_id,role) VALUES('preview-member','preview-org','preview-user','viewer')")
            .execute(&f.pool)
            .await?;
        anyhow::ensure!(f.proxied_with_grant(&token).await? == StatusCode::OK);
        anyhow::ensure!(f.proxied_as(&bearer("preview-user"), &no_cookie).await? == StatusCode::OK);
        Ok(())
    }
    .await;
    result.and(f.cleanup().await)
}
