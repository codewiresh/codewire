//! The Connect auth layer's admission check: the mount's credential policy,
//! then product access and the admin gate.

use super::*;
use crate::auth::Authentication;
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
                if again.as_ref() == Some(admitted) {
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
/// request's user and credential, then runs the request's admission again,
/// so a revocation either refuses it here or ends it later. Refused as
/// `unauthenticated` when the credential no longer admits it, and as
/// `unavailable` when that couldn't be checked; never admitted unchecked.
pub async fn admit_stream(
    ctx: &connectrpc::RequestContext,
    fence: &Fence,
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
    let watch = fence
        .admit(
            &recheck.layer.state.pool,
            &admitted,
            recheck.recheck(&admitted),
        )
        .await
        .map_err(|refused| match refused {
            Refused::Revoked => connectrpc::ConnectError::unauthenticated("access revoked"),
            Refused::Unavailable => {
                connectrpc::ConnectError::unavailable("stream admission is unavailable; try again")
            }
        })?;
    Ok((admitted, watch))
}
