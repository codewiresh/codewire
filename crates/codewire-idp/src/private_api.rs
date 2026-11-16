//! Keeps every IdP API answer out of shared caches.
//!
//! An answer under `/api/` depends on the caller's cookie or `Authorization`
//! header, so a shared cache that stored one would serve it to the next
//! caller. The rule is in `docs/dev/AUTH-POLICY.md` ("Credential
//! rules"). Caller-independent documents outside `/api/`, such
//! as discovery and the JWKS under `/.well-known/`, keep their own caching.

use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, header},
    middleware::{self, Next},
    response::Response,
};

const API_PREFIX: &str = "/api/";
const PRIVATE_NO_STORE: &str = "no-store, private";

/// Wraps the IdP's assembled router so every response under `/api/`,
/// including errors and the 404 fallback, carries
/// `Cache-Control: no-store, private` and no `ETag` or `Last-Modified`.
///
/// Apply it after the last `merge`: a router merged later is not covered.
pub fn private_api_responses(router: Router) -> Router {
    router.layer(middleware::from_fn(mark_private))
}

async fn mark_private(request: Request, next: Next) -> Response {
    let private = request.uri().path().starts_with(API_PREFIX);
    let mut response = next.run(request).await;
    if private {
        let headers = response.headers_mut();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(PRIVATE_NO_STORE),
        );
        headers.remove(header::ETAG);
        headers.remove(header::LAST_MODIFIED);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_session::{SignupInvitePolicy, router as session_router};
    use axum::{body::Body, http::StatusCode, response::IntoResponse, routing::get};
    use sqlx::PgPool;
    use tower::ServiceExt;

    /// Headers a handler or an upstream might add that let a shared cache
    /// store or revalidate an answer.
    fn cacheable_headers() -> [(header::HeaderName, &'static str); 3] {
        [
            (header::CACHE_CONTROL, "public, max-age=300"),
            (header::ETAG, "\"synthetic-etag\""),
            (header::LAST_MODIFIED, "Mon, 16 Nov 2026 12:00:00 GMT"),
        ]
    }

    /// The session routes as `main` mounts them, beside stand-ins for a
    /// handler that sets its own cache headers and for the public
    /// discovery and JWKS documents. The pool is lazy: these requests never
    /// reach the database, or reach a closed one on purpose.
    fn app(pool: PgPool) -> Router {
        let stand_ins = Router::new()
            .route(
                "/api/auth/stand-in",
                get(|| async {
                    (
                        [
                            (header::CACHE_CONTROL, "no-store"),
                            (header::ETAG, "\"synthetic-etag\""),
                            (header::LAST_MODIFIED, "Mon, 16 Nov 2026 12:00:00 GMT"),
                        ],
                        "{}",
                    )
                        .into_response()
                }),
            )
            .route(
                "/.well-known/openid-configuration",
                get(|| async { (cacheable_headers(), "{}").into_response() }),
            )
            .route(
                "/.well-known/jwks.json",
                get(|| async { (cacheable_headers(), "{}").into_response() }),
            );
        private_api_responses(
            session_router(pool, true, SignupInvitePolicy::open()).merge(stand_ins),
        )
    }

    fn lazy_pool() -> PgPool {
        PgPool::connect_lazy("postgres://localhost/none").unwrap()
    }

    async fn get_response(app: Router, path: &str, cookie: Option<&str>) -> Response {
        let mut request = Request::builder().method("GET").uri(path);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        app.oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn assert_private(response: &Response) {
        let headers = response.headers();
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store, private"
        );
        assert!(headers.get(header::ETAG).is_none());
        assert!(headers.get(header::LAST_MODIFIED).is_none());
    }

    #[tokio::test]
    async fn signed_out_get_session_is_private() {
        let response = get_response(app(lazy_pool()), "/api/auth/get-session", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_private(&response);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"null");
    }

    #[tokio::test]
    async fn api_errors_are_private() {
        let pool = lazy_pool();
        pool.close().await;
        let failed = get_response(
            app(pool.clone()),
            "/api/auth/get-session",
            Some("codewire.session_token=synthetic-session"),
        )
        .await;
        assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_private(&failed);

        let missing = get_response(app(pool), "/api/auth/no-such-route", None).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_private(&missing);
    }

    #[tokio::test]
    async fn a_handlers_own_cache_headers_give_way_under_api() {
        let response = get_response(app(lazy_pool()), "/api/auth/stand-in", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_private(&response);
    }

    #[tokio::test]
    async fn public_documents_keep_their_own_caching() {
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
        ] {
            let response = get_response(app(lazy_pool()), path, None).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            for (name, value) in cacheable_headers() {
                assert_eq!(response.headers().get(&name).unwrap(), value, "{path}");
            }
        }
    }
}
