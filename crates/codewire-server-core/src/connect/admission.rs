//! The Connect auth layer's admission check: the mount's credential policy,
//! then product access and the admin gate.

use super::*;
use crate::auth::Authentication;
use crate::error::BEARER_REFUSED_CODE;
use crate::revocation::{Admitted, Fence, Refused, Watch};

/// Why the layer refused a request.
pub(super) enum Refusal {
    /// No credential was resolved, or resolving one failed or timed out.
    Unresolved {
        failure: AuthResolutionFailure,
        timeout: Duration,
    },
    /// A credential was resolved, but it may not use this mount or method.
    Unauthorized {
        error: AppError,
        auth: Box<Authentication>,
    },
}

/// Admits a request to `layer`'s mount at `path` with `headers`.
pub(super) async fn admit(
    layer: &ConnectAuthLayer,
    headers: &http::HeaderMap,
    path: &str,
) -> Result<(Authentication, Option<CredentialMutationAuthority>), Refusal> {
    let timeout = connect_auth_resolution_timeout(headers);
    let (auth, mutation_authority) = bounded_authentication(
        async {
            match layer.credential_policy {
                ConnectCredentialPolicy::Product => resolve_authentication(
                    &layer.state,
                    session_cookie(headers),
                    bearer_token(headers),
                )
                .await
                .map(|auth| (auth, None)),
                ConnectCredentialPolicy::OAuthBearerOnly => {
                    resolve_oauth_bearer_authentication(&layer.state, headers)
                        .await
                        .map(|auth| (auth, None))
                }
                ConnectCredentialPolicy::CredentialMutation => {
                    let origin = layer
                        .session_origin
                        .as_ref()
                        .expect("credential mutation policy has a session origin");
                    resolve_credential_mutation_authentication(&layer.state, headers, origin)
                        .await
                        .map(|(auth, authority)| (auth, Some(authority)))
                }
            }
        },
        timeout,
    )
    .await
    .map_err(|failure| Refusal::Unresolved { failure, timeout })?;

    let refused = if let Err(error) = require_product_access(&auth) {
        Some(error)
    } else if layer.admin_mount || layer.admin_methods.contains(path) {
        auth.user.require_global_admin().err()
    } else {
        None
    };
    match refused {
        Some(error) => Err(Refusal::Unauthorized {
            error,
            auth: Box::new(auth),
        }),
        None => Ok((auth, mutation_authority)),
    }
}

/// Gives the layer's own refusal of a presented bearer its own code,
/// [`BEARER_REFUSED_CODE`], which is also its `ErrorInfo` reason. It comes
/// before any handler runs, so a native client refreshes once and sends the
/// call again (`docs/dev/AUTH-POLICY.md`, "Native sign-in lifetimes"). A
/// refused cookie, and every other failure, keeps its own answer.
pub(super) fn mark_bearer_refusal(
    failure: AuthResolutionFailure,
    headers: &http::HeaderMap,
) -> AuthResolutionFailure {
    match failure {
        AuthResolutionFailure::Authentication(AppError::Unauthorized)
            if bearer_token(headers).is_some() =>
        {
            AuthResolutionFailure::Authentication(AppError::Coded {
                status: StatusCode::UNAUTHORIZED,
                code: BEARER_REFUSED_CODE,
                detail: "unauthorized".into(),
            })
        }
        failure => failure,
    }
}

/// A request's own admission, kept so a stream it opens can run it again
/// ([`crate::revocation`], #3586).
#[derive(Clone)]
pub struct AdmissionRecheck {
    layer: Arc<ConnectAuthLayer>,
    headers: http::HeaderMap,
    path: String,
}

impl AdmissionRecheck {
    pub(super) fn new(
        layer: Arc<ConnectAuthLayer>,
        headers: http::HeaderMap,
        path: String,
    ) -> Self {
        Self {
            layer,
            headers,
            path,
        }
    }

    /// Runs the admission again, and refuses unless it admits the same user
    /// with the same credential. A credential no longer accepted refuses as
    /// revoked; a check that failed or timed out refuses as unavailable.
    async fn recheck(&self, admitted: &Admitted) -> Result<(), Refused> {
        match admit(&self.layer, &self.headers, &self.path).await {
            Ok((auth, _)) => {
                let again = Admitted::from_request(
                    &auth.user,
                    &auth.credential,
                    auth.oauth_bearer_authority.as_ref(),
                );
                if again.is_some_and(|again| again.same_credential(admitted)) {
                    Ok(())
                } else {
                    Err(Refused::Revoked)
                }
            }
            Err(
                Refusal::Unauthorized { .. }
                | Refusal::Unresolved {
                    failure:
                        AuthResolutionFailure::Authentication(
                            AppError::Unauthorized | AppError::Forbidden,
                        ),
                    ..
                },
            ) => Err(Refused::Revoked),
            Err(Refusal::Unresolved { .. }) => Err(Refused::Unavailable),
        }
    }
}

/// Admits a stream this request opens to `fence`: registers it under the
/// request's user and credential, and under `org_id` when the stream goes
/// into one of its environments, then runs the request's admission again,
/// so a revocation either refuses it here or ends it later. Refused as
/// `unauthenticated` when the credential no longer admits it, and as
/// `unavailable` when that couldn't be checked; never admitted unchecked.
pub async fn admit_stream(
    ctx: &connectrpc::RequestContext,
    fence: &Fence,
    org_id: Option<&str>,
) -> Result<(Admitted, Watch), connectrpc::ConnectError> {
    let recheck = ctx
        .extensions()
        .get::<AdmissionRecheck>()
        .ok_or_else(|| connectrpc::ConnectError::internal("stream opened without its admission"))?;
    let admitted = Admitted::from_request(
        auth_user(ctx)?,
        auth_context(ctx)?,
        ctx.extensions().get::<OAuthBearerAuthority>(),
    )
    .ok_or_else(|| connectrpc::ConnectError::unauthenticated("access revoked"))?;
    let admitted = match org_id {
        Some(org_id) => admitted.in_organization(org_id),
        None => admitted,
    };
    let watch = fence
        .admit(
            &recheck.layer.state.pool,
            &admitted,
            recheck.recheck(&admitted),
        )
        .await
        .map_err(|refused| match refused {
            Refused::Revoked => connectrpc::ConnectError::unauthenticated("access revoked"),
            // As the request's own access check answers, which a stream's
            // admission runs before (#3586).
            Refused::NotMember => connectrpc::ConnectError::not_found("organization not found"),
            Refused::OrganizationDeleting => {
                crate::revocation::ended_error(crate::revocation::Revocation::Organization)
            }
            Refused::Unavailable => {
                connectrpc::ConnectError::unavailable("stream admission is unavailable; try again")
            }
        })?;
    Ok((admitted, watch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_static(value));
        }
        headers
    }

    fn code(failure: &AuthResolutionFailure) -> Option<String> {
        match failure {
            AuthResolutionFailure::Authentication(error) => error.code().map(String::from),
            AuthResolutionFailure::DeadlineExceeded => None,
        }
    }

    #[test]
    fn only_a_refused_bearer_is_marked() {
        let bearer = headers(&[("authorization", "Bearer refused")]);
        let marked = mark_bearer_refusal(
            AuthResolutionFailure::Authentication(AppError::Unauthorized),
            &bearer,
        );
        assert_eq!(code(&marked).as_deref(), Some(BEARER_REFUSED_CODE));
        let AuthResolutionFailure::Authentication(error) = &marked else {
            panic!("a marked refusal stays an authentication failure");
        };
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);

        let cookie = headers(&[("cookie", "codewire.session_token=refused")]);
        let kept = mark_bearer_refusal(
            AuthResolutionFailure::Authentication(AppError::Unauthorized),
            &cookie,
        );
        assert_eq!(code(&kept).as_deref(), Some("session_expired"));

        let forbidden = mark_bearer_refusal(
            AuthResolutionFailure::Authentication(AppError::Forbidden),
            &bearer,
        );
        assert_eq!(code(&forbidden).as_deref(), Some("forbidden"));

        let timed_out = mark_bearer_refusal(AuthResolutionFailure::DeadlineExceeded, &bearer);
        assert!(matches!(timed_out, AuthResolutionFailure::DeadlineExceeded));
    }
}
